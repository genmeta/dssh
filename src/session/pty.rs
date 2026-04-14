//! PTY allocation and terminal control for SSH3 sessions.
//!
//! Handles `pty-req` and `window-change` channel requests per RFC 4254
//! Sections 6.2 and 6.7.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
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
#[snafu(display("pty dimension overflow: {field} = {value} exceeds u16::MAX"))]
pub struct DimensionOverflow {
    pub field: &'static str,
    pub value: u32,
}

/// Errors from PTY allocation or terminal resize operations.
#[derive(Debug, Snafu)]
pub enum PtyError {
    #[snafu(display("invalid terminal dimension"))]
    Dimension { source: DimensionOverflow },

    #[snafu(display("pty system call failed"))]
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
// Terminal modes (RFC 4254 §8)
// ============================================================================

/// Opcodes that end mode parsing or set baud rate.
const TTY_OP_END: u8 = 0;
const TTY_OP_ISPEED: u8 = 128;
const TTY_OP_OSPEED: u8 = 129;

/// Apply encoded terminal modes (from an SSH pty-req) to a PTY slave fd.
///
/// The encoding follows RFC 4254 §8: each entry is a `u8` opcode followed by
/// a `u32` value. Opcode 0 terminates the list. Opcodes 1–159 each take a
/// `u32` argument. Opcodes 160–255 are undefined and stop parsing.
///
/// The function does a `tcgetattr` → modify → `tcsetattr(TCSANOW)` cycle.
/// Unknown opcodes in 1–159 are silently skipped. Errors from individual
/// mode settings are logged but do not abort processing.
pub fn apply_terminal_modes(fd: RawFd, modes: &[u8]) -> Result<(), PtyError> {
    if modes.is_empty() {
        return Ok(());
    }

    // SAFETY: fd is a valid open PTY slave fd owned by the caller.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut tio = nix::sys::termios::tcgetattr(borrowed).context(OsSnafu)?;
    let mut pos = 0;

    while pos < modes.len() {
        let opcode = modes[pos];
        pos += 1;

        if opcode == TTY_OP_END {
            break;
        }

        // Opcodes 160-255 are undefined; stop parsing.
        if opcode >= 160 {
            tracing::debug!(opcode, "stopping terminal mode parse at undefined opcode");
            break;
        }

        // All opcodes 1-159 consume a u32 argument.
        if pos + 4 > modes.len() {
            tracing::warn!(opcode, "truncated terminal modes data");
            break;
        }
        let value = u32::from_be_bytes([modes[pos], modes[pos + 1], modes[pos + 2], modes[pos + 3]]);
        pos += 4;

        match opcode {
            TTY_OP_ISPEED => {
                if let Some(speed) = baud_to_speed(value) {
                    let _ = nix::sys::termios::cfsetispeed(&mut tio, speed);
                }
            }
            TTY_OP_OSPEED => {
                if let Some(speed) = baud_to_speed(value) {
                    let _ = nix::sys::termios::cfsetospeed(&mut tio, speed);
                }
            }
            // Special characters (opcodes 1–18).
            op @ 1..=18 => {
                if let Some(idx) = cc_index(op) {
                    tio.control_chars[idx] = if value == 255 { 0 } else { value as u8 };
                }
            }
            // Input flags (opcodes 30–42).
            op @ 30..=42 => {
                if let Some(flag) = iflag_bit(op) {
                    if value != 0 {
                        tio.input_flags |= flag;
                    } else {
                        tio.input_flags &= !flag;
                    }
                }
            }
            // Local flags (opcodes 50–62).
            op @ 50..=62 => {
                if let Some(flag) = lflag_bit(op) {
                    if value != 0 {
                        tio.local_flags |= flag;
                    } else {
                        tio.local_flags &= !flag;
                    }
                }
            }
            // Output flags (opcodes 70–75).
            op @ 70..=75 => {
                if let Some(flag) = oflag_bit(op) {
                    if value != 0 {
                        tio.output_flags |= flag;
                    } else {
                        tio.output_flags &= !flag;
                    }
                }
            }
            // Control flags (opcodes 90–93).
            op @ 90..=93 => {
                if let Some(flag) = cflag_bit(op) {
                    if value != 0 {
                        tio.control_flags |= flag;
                    } else {
                        tio.control_flags &= !flag;
                    }
                }
            }
            _ => {
                // Unknown but valid opcode (1-159); already consumed the u32.
                tracing::trace!(opcode, "ignoring unknown terminal mode opcode");
            }
        }
    }

    nix::sys::termios::tcsetattr(borrowed, nix::sys::termios::SetArg::TCSANOW, &tio).context(OsSnafu)?;
    Ok(())
}

/// Map a baud rate integer to a `nix::sys::termios::BaudRate`.
fn baud_to_speed(baud: u32) -> Option<nix::sys::termios::BaudRate> {
    use nix::sys::termios::BaudRate;
    Some(match baud {
        0 => BaudRate::B0,
        50 => BaudRate::B50,
        75 => BaudRate::B75,
        110 => BaudRate::B110,
        134 => BaudRate::B134,
        150 => BaudRate::B150,
        200 => BaudRate::B200,
        300 => BaudRate::B300,
        600 => BaudRate::B600,
        1200 => BaudRate::B1200,
        1800 => BaudRate::B1800,
        2400 => BaudRate::B2400,
        4800 => BaudRate::B4800,
        9600 => BaudRate::B9600,
        19200 => BaudRate::B19200,
        38400 => BaudRate::B38400,
        57600 => BaudRate::B57600,
        115200 => BaudRate::B115200,
        230400 => BaudRate::B230400,
        _ => return None,
    })
}

/// Map TTYCHAR opcode (1–18) to `nix::sys::termios::SpecialCharacterIndices` index.
fn cc_index(opcode: u8) -> Option<usize> {
    use nix::sys::termios::SpecialCharacterIndices as CC;
    let idx = match opcode {
        1 => CC::VINTR,
        2 => CC::VQUIT,
        3 => CC::VERASE,
        4 => CC::VKILL,
        5 => CC::VEOF,
        6 => CC::VEOL,
        7 => CC::VEOL2,
        8 => CC::VSTART,
        9 => CC::VSTOP,
        10 => CC::VSUSP,
        12 => CC::VREPRINT,
        13 => CC::VWERASE,
        14 => CC::VLNEXT,
        18 => CC::VDISCARD,
        _ => return None,
    };
    Some(idx as usize)
}

/// Map iflag opcode (30–42) to `nix::sys::termios::InputFlags` bit.
fn iflag_bit(opcode: u8) -> Option<nix::sys::termios::InputFlags> {
    use nix::sys::termios::InputFlags;
    Some(match opcode {
        30 => InputFlags::IGNPAR,
        31 => InputFlags::PARMRK,
        32 => InputFlags::INPCK,
        33 => InputFlags::ISTRIP,
        34 => InputFlags::INLCR,
        35 => InputFlags::IGNCR,
        36 => InputFlags::ICRNL,
        38 => InputFlags::IXON,
        39 => InputFlags::IXANY,
        40 => InputFlags::IXOFF,
        41 => InputFlags::IMAXBEL,
        42 => InputFlags::IUTF8,
        _ => return None,
    })
}

/// Map lflag opcode (50–62) to `nix::sys::termios::LocalFlags` bit.
fn lflag_bit(opcode: u8) -> Option<nix::sys::termios::LocalFlags> {
    use nix::sys::termios::LocalFlags;
    Some(match opcode {
        50 => LocalFlags::ISIG,
        51 => LocalFlags::ICANON,
        53 => LocalFlags::ECHO,
        54 => LocalFlags::ECHOE,
        55 => LocalFlags::ECHOK,
        56 => LocalFlags::ECHONL,
        57 => LocalFlags::NOFLSH,
        58 => LocalFlags::TOSTOP,
        59 => LocalFlags::IEXTEN,
        60 => LocalFlags::ECHOCTL,
        61 => LocalFlags::ECHOKE,
        62 => LocalFlags::PENDIN,
        _ => return None,
    })
}

/// Map oflag opcode (70–75) to `nix::sys::termios::OutputFlags` bit.
fn oflag_bit(opcode: u8) -> Option<nix::sys::termios::OutputFlags> {
    use nix::sys::termios::OutputFlags;
    Some(match opcode {
        70 => OutputFlags::OPOST,
        72 => OutputFlags::ONLCR,
        73 => OutputFlags::OCRNL,
        74 => OutputFlags::ONOCR,
        75 => OutputFlags::ONLRET,
        _ => return None,
    })
}

/// Map cflag opcode (90–93) to `nix::sys::termios::ControlFlags` bit.
fn cflag_bit(opcode: u8) -> Option<nix::sys::termios::ControlFlags> {
    use nix::sys::termios::ControlFlags;
    Some(match opcode {
        90 => ControlFlags::CS7,
        91 => ControlFlags::CS8,
        92 => ControlFlags::PARENB,
        93 => ControlFlags::PARODD,
        _ => return None,
    })
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
