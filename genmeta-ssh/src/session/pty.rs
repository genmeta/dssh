//! PTY allocation and terminal control for SSH3 sessions.
//!
//! Handles `pty-req` and `window-change` channel requests per RFC 4254
//! Sections 6.2 and 6.7.

use std::os::fd::{AsRawFd, OwnedFd};

use nix::libc;
use nix::pty::{openpty, Winsize};
use snafu::prelude::*;

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
pub fn set_window_size(master: &impl AsRawFd, request: &WindowChangeRequest) -> Result<(), PtyError> {
    let ws = winsize_from_resize(request).context(DimensionSnafu)?;
    // SAFETY: TIOCSWINSZ writes the winsize struct to the terminal driver.
    unsafe { tiocswinsz(master.as_raw_fd(), &ws as *const libc::winsize) }.context(OsSnafu)?;
    Ok(())
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
        let err = set_window_size(&pair.master, &resize_request(80, u16::MAX as u32 + 1, 0, 0)).unwrap_err();
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
