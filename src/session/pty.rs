//! PTY allocation and terminal control for SSH3 sessions.
//!
//! Handles `pty-req` and `window-change` channel requests per RFC 4254
//! Sections 6.2 and 6.7.

use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::task::Context;

use nix::libc;
use nix::pty::{Winsize, openpty};
use snafu::prelude::*;
use tokio::io;

use crate::session::{PtyRequest, WindowChangeRequest};

nix::ioctl_write_ptr_bad!(tiocswinsz, libc::TIOCSWINSZ, libc::winsize);
#[cfg(test)]
nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);

// ============================================================================
// Types
// ============================================================================

/// A master/slave PTY pair with owned file descriptors.
#[derive(Debug)]
pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

// ============================================================================
// Error types
// ============================================================================

/// A terminal dimension value exceeds `u16::MAX`.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(display("PTY dimension overflow: {field} = {value} exceeds u16::MAX"))]
pub struct DimensionOverflow {
    pub field: &'static str,
    pub value: u32,
}

/// Errors from PTY allocation or terminal resize operations.
#[derive(Debug, Snafu)]
pub enum PtyError {
    #[snafu(display("invalid terminal dimension"))]
    Dimension { source: DimensionOverflow },

    #[snafu(display("PTY system call failed"))]
    Os { source: nix::Error },
}

// ============================================================================
// Dimension conversion
// ============================================================================

fn try_u16(value: u64, field: &'static str) -> Result<u16, DimensionOverflow> {
    u16::try_from(value).map_err(|_| DimensionOverflow {
        field,
        value: value as u32,
    })
}

fn winsize_from_pty(request: &PtyRequest) -> Result<libc::winsize, DimensionOverflow> {
    Ok(libc::winsize {
        ws_col: try_u16(request.width_cols.into_inner(), "width_cols")?,
        ws_row: try_u16(request.height_rows.into_inner(), "height_rows")?,
        ws_xpixel: try_u16(request.width_px.into_inner(), "width_px")?,
        ws_ypixel: try_u16(request.height_px.into_inner(), "height_px")?,
    })
}

fn winsize_from_resize(request: &WindowChangeRequest) -> Result<libc::winsize, DimensionOverflow> {
    Ok(libc::winsize {
        ws_col: try_u16(request.width_cols.into_inner(), "width_cols")?,
        ws_row: try_u16(request.height_rows.into_inner(), "height_rows")?,
        ws_xpixel: try_u16(request.width_px.into_inner(), "width_px")?,
        ws_ypixel: try_u16(request.height_px.into_inner(), "height_px")?,
    })
}

// ============================================================================
// Public API
// ============================================================================

/// Allocate a new PTY pair with the requested terminal size.
///
/// Returns `Err` if any dimension overflows `u16` or if `openpty` fails.
pub fn allocate_pty(request: &PtyRequest) -> Result<PtyPair, PtyError> {
    let ws = winsize_from_pty(request).context(DimensionSnafu)?;
    let winsize = Winsize {
        ws_row: ws.ws_row,
        ws_col: ws.ws_col,
        ws_xpixel: ws.ws_xpixel,
        ws_ypixel: ws.ws_ypixel,
    };

    let result = openpty(Some(&winsize), None).context(OsSnafu)?;
    Ok(PtyPair {
        master: result.master,
        slave: result.slave,
    })
}

/// Update the terminal window size of an existing PTY.
///
/// Returns `Err` if any dimension overflows `u16` or if the ioctl fails.
pub fn set_window_size(
    master: &impl AsRawFd,
    request: &WindowChangeRequest,
) -> Result<(), PtyError> {
    set_window_size_raw(master.as_raw_fd(), request)
}

/// Update the terminal window size via a raw file descriptor.
///
/// # Safety
/// The caller must ensure `fd` is a valid open PTY master file descriptor.
pub fn set_window_size_raw(
    fd: std::os::fd::RawFd,
    request: &WindowChangeRequest,
) -> Result<(), PtyError> {
    let ws = winsize_from_resize(request).context(DimensionSnafu)?;
    // SAFETY: TIOCSWINSZ writes the winsize struct to the terminal driver.
    unsafe { tiocswinsz(fd, &ws as *const libc::winsize) }.context(OsSnafu)?;
    Ok(())
}

// ============================================================================
// Async PTY I/O via epoll (AsyncFd)
// ============================================================================

/// Async wrapper around a PTY master file descriptor.
///
/// Uses [`tokio::io::unix::AsyncFd`] with epoll for non-blocking I/O,
/// unlike `tokio::fs::File` which routes every operation through
/// `spawn_blocking` and serializes reads and writes.
pub struct AsyncPtyFd {
    inner: io::unix::AsyncFd<OwnedFd>,
}

impl AsyncPtyFd {
    /// Wrap an owned PTY master fd for async I/O.
    ///
    /// Sets `O_NONBLOCK` on the fd and registers it with the tokio reactor.
    pub fn new(fd: OwnedFd) -> std::io::Result<Self> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let flags = fcntl(&fd, FcntlArg::F_GETFL).map_err(std::io::Error::from)?;
        let mut oflags = OFlag::from_bits_truncate(flags);
        oflags |= OFlag::O_NONBLOCK;
        fcntl(&fd, FcntlArg::F_SETFL(oflags)).map_err(std::io::Error::from)?;
        Ok(Self {
            inner: io::unix::AsyncFd::new(fd)?,
        })
    }

    /// Returns the raw file descriptor.
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl io::AsyncRead for AsyncPtyFd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            let mut guard = std::task::ready!(self.inner.poll_read_ready(cx))?;
            match guard.try_io(|inner| {
                nix::unistd::read(inner.get_ref(), buf.initialize_unfilled())
                    .map_err(std::io::Error::from)
            }) {
                Ok(result) => {
                    buf.advance(result?);
                    return std::task::Poll::Ready(Ok(()));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

impl io::AsyncWrite for AsyncPtyFd {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        loop {
            let mut guard = std::task::ready!(self.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                nix::unistd::write(inner.get_ref(), buf).map_err(std::io::Error::from)
            }) {
                Ok(result) => return std::task::Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SshBytes;
    use h3x::varint::VarInt;

    fn pty_request(cols: u32, rows: u32, px_w: u32, px_h: u32) -> PtyRequest {
        PtyRequest {
            term_type: "xterm-256color".into(),
            width_cols: VarInt::from(cols),
            height_rows: VarInt::from(rows),
            width_px: VarInt::from(px_w),
            height_px: VarInt::from(px_h),
            terminal_modes: SshBytes::from(vec![]),
        }
    }

    fn resize_request(cols: u32, rows: u32, px_w: u32, px_h: u32) -> WindowChangeRequest {
        WindowChangeRequest {
            width_cols: VarInt::from(cols),
            height_rows: VarInt::from(rows),
            width_px: VarInt::from(px_w),
            height_px: VarInt::from(px_h),
        }
    }

    #[test]
    fn allocate_returns_valid_fds() {
        let pair = allocate_pty(&pty_request(80, 24, 0, 0)).unwrap();
        assert!(pair.master.as_raw_fd() >= 0);
        assert!(pair.slave.as_raw_fd() >= 0);
        assert_ne!(pair.master.as_raw_fd(), pair.slave.as_raw_fd());
    }

    #[test]
    fn allocate_sets_initial_size() {
        let pair = allocate_pty(&pty_request(132, 43, 1056, 688)).unwrap();
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { tiocgwinsz(pair.master.as_raw_fd(), &mut ws) }.unwrap();
        assert_eq!(ws.ws_col, 132);
        assert_eq!(ws.ws_row, 43);
        assert_eq!(ws.ws_xpixel, 1056);
        assert_eq!(ws.ws_ypixel, 688);
    }

    #[test]
    fn resize_updates_size() {
        let pair = allocate_pty(&pty_request(80, 24, 0, 0)).unwrap();
        set_window_size(&pair.master, &resize_request(120, 40, 960, 800)).unwrap();
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { tiocgwinsz(pair.master.as_raw_fd(), &mut ws) }.unwrap();
        assert_eq!(ws.ws_col, 120);
        assert_eq!(ws.ws_row, 40);
        assert_eq!(ws.ws_xpixel, 960);
        assert_eq!(ws.ws_ypixel, 800);
    }

    #[test]
    fn allocate_rejects_overflow() {
        let err = allocate_pty(&pty_request(u16::MAX as u32 + 1, 24, 0, 0)).unwrap_err();
        assert!(matches!(err, PtyError::Dimension { source } if source.field == "width_cols"));
    }

    #[test]
    fn resize_rejects_overflow() {
        let pair = allocate_pty(&pty_request(80, 24, 0, 0)).unwrap();
        let err = set_window_size(&pair.master, &resize_request(80, u16::MAX as u32 + 1, 0, 0))
            .unwrap_err();
        assert!(matches!(err, PtyError::Dimension { source } if source.field == "height_rows"));
    }

    #[test]
    fn dimension_at_u16_max_accepted() {
        let max = u16::MAX as u32;
        let pair = allocate_pty(&pty_request(max, max, max, max)).unwrap();
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { tiocgwinsz(pair.master.as_raw_fd(), &mut ws) }.unwrap();
        assert_eq!(ws.ws_col, u16::MAX);
        assert_eq!(ws.ws_row, u16::MAX);
    }
}
