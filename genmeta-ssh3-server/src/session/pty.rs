//! PTY allocation and terminal handling for SSH3 sessions.
//!
//! Handles `pty-req`, `window-change`, and `signal` ChannelRequest types
//! per RFC 4254 Sections 6.2, 6.7.

use std::os::fd::{OwnedFd, RawFd};

use genmeta_ssh::{PtyRequest, WindowChangeRequest};
use nix::pty::{openpty, Winsize};
use snafu::{ResultExt, Snafu};

nix::ioctl_write_ptr_bad!(tiocswinsz, libc::TIOCSWINSZ, libc::winsize);
#[cfg(test)]
nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);

/// A master/slave PTY pair with owned file descriptors.
#[derive(Debug)]
pub struct PtyPair {
    /// The master side of the PTY pair.
    pub master: OwnedFd,
    /// The slave side of the PTY pair.
    pub slave: OwnedFd,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Checked u32→u16 dimension conversion
// ---------------------------------------------------------------------------

/// Error returned when an RFC `uint32` dimension value exceeds `u16::MAX`
/// and cannot be used for the ioctl `winsize` struct.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(display("PTY dimension overflow: {field} = {value} exceeds u16::MAX (65535)"))]
pub struct DimensionOverflow {
    /// Name of the overflowing field (e.g., "width_cols").
    pub field: &'static str,
    /// The value that overflowed.
    pub value: u32,
}

/// Attempt checked conversion of all four PTY dimension fields from `u32` to `u16`.
///
/// Returns `Ok(winsize)` if all values fit, or `Err(DimensionOverflow)` identifying
/// the first field that overflows.
pub fn checked_winsize(
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
) -> Result<libc::winsize, DimensionOverflow> {
    if width_cols > u16::MAX as u32 {
        return Err(DimensionOverflow {
            field: "width_cols",
            value: width_cols,
        });
    }
    if height_rows > u16::MAX as u32 {
        return Err(DimensionOverflow {
            field: "height_rows",
            value: height_rows,
        });
    }
    if width_px > u16::MAX as u32 {
        return Err(DimensionOverflow {
            field: "width_px",
            value: width_px,
        });
    }
    if height_px > u16::MAX as u32 {
        return Err(DimensionOverflow {
            field: "height_px",
            value: height_px,
        });
    }

    let ws_col = width_cols as u16;
    let ws_row = height_rows as u16;
    let ws_xpixel = width_px as u16;
    let ws_ypixel = height_px as u16;

    Ok(libc::winsize {
        ws_row,
        ws_col,
        ws_xpixel,
        ws_ypixel,
    })
}

/// Validate that a [`PtyRequest`]'s dimensions fit in `u16`.
///
/// Returns `Ok(winsize)` or `Err(DimensionOverflow)`.
pub fn validate_pty_dimensions(request: &PtyRequest) -> Result<libc::winsize, DimensionOverflow> {
    checked_winsize(
        request.width_cols,
        request.height_rows,
        request.width_px,
        request.height_px,
    )
}

/// Validate that a [`WindowChangeRequest`]'s dimensions fit in `u16`.
///
/// Returns `Ok(winsize)` or `Err(DimensionOverflow)`.
pub fn validate_window_change_dimensions(
    request: &WindowChangeRequest,
) -> Result<libc::winsize, DimensionOverflow> {
    checked_winsize(
        request.width_cols,
        request.height_rows,
        request.width_px,
        request.height_px,
    )
}

/// Errors arising from PTY allocation or terminal resize operations.
#[derive(Debug, Snafu)]
pub enum PtyError {
    /// A dimension value overflows `u16` and cannot be used for ioctl winsize.
    #[snafu(display("{source}"))]
    Dimension { source: DimensionOverflow },

    /// An OS-level error from `openpty` or `ioctl`.
    #[snafu(display("PTY OS error"))]
    Os { source: nix::Error },
}

/// Allocate a new PTY pair with the requested terminal size.
///
/// Uses `nix::pty::openpty` to create the master/slave pair, then sets the
/// terminal size via ioctl `TIOCSWINSZ`.
///
/// Returns `Err` if any dimension overflows `u16` (no silent truncation) or
/// if the underlying `openpty` call fails.
pub fn allocate_pty(request: &PtyRequest) -> Result<PtyPair, PtyError> {
    let ws = validate_pty_dimensions(request).context(DimensionSnafu)?;
    let winsize = Winsize {
        ws_row: ws.ws_row,
        ws_col: ws.ws_col,
        ws_xpixel: ws.ws_xpixel,
        ws_ypixel: ws.ws_ypixel,
    };

    let pty_result = openpty(Some(&winsize), None).context(OsSnafu)?;

    Ok(PtyPair {
        master: pty_result.master,
        slave: pty_result.slave,
    })
}

/// Update the terminal size of an existing PTY via ioctl `TIOCSWINSZ`.
///
/// Returns `Err` if any dimension overflows `u16` (no silent truncation) or
/// if the ioctl fails.
pub fn set_window_size(master_fd: RawFd, request: &WindowChangeRequest) -> Result<(), PtyError> {
    let winsize =
        validate_window_change_dimensions(request).context(DimensionSnafu)?;

    unsafe { tiocswinsz(master_fd, &winsize as *const libc::winsize) }.context(OsSnafu)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use h3x::codec::{DecodeExt, EncodeExt};
    use genmeta_ssh::SignalRequest;

    // -------------------------------------------------------------------
    // Test 1: parse_pty_request roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_pty_request_roundtrip() {
        let original = PtyRequest {
            term_type: "xterm-256color".into(),
            width_cols: 80,
            height_rows: 24,
            width_px: 640,
            height_px: 480,
            terminal_modes: vec![0x01, 0x00, 0x00, 0x00, 0x03],
        };

        let mut encoded = Vec::new();
        encoded.encode_one(&original).await.unwrap();
        let mut reader = encoded.as_slice();
        let parsed: PtyRequest = reader.decode_one().await.unwrap();

        assert_eq!(parsed.term_type, original.term_type);
        assert_eq!(parsed.width_cols, original.width_cols);
        assert_eq!(parsed.height_rows, original.height_rows);
        assert_eq!(parsed.width_px, original.width_px);
        assert_eq!(parsed.height_px, original.height_px);
        assert_eq!(parsed.terminal_modes, original.terminal_modes);
    }

    // -------------------------------------------------------------------
    // Test 2: window-change codec roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn window_change_codec_roundtrip() {
        let original = WindowChangeRequest {
            width_cols: 120,
            height_rows: 40,
            width_px: 960,
            height_px: 800,
        };

        let mut encoded = Vec::new();
        encoded.encode_one(&original).await.unwrap();
        let mut reader = encoded.as_slice();
        let parsed: WindowChangeRequest = reader.decode_one().await.unwrap();

        assert_eq!(parsed.width_cols, original.width_cols);
        assert_eq!(parsed.height_rows, original.height_rows);
        assert_eq!(parsed.width_px, original.width_px);
        assert_eq!(parsed.height_px, original.height_px);
    }

    // -------------------------------------------------------------------
    // Test 3: signal codec roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn signal_codec_roundtrip() {
        let original = SignalRequest {
            signal_name: "INT".into(),
        };

        let mut encoded = Vec::new();
        encoded.encode_one(&original).await.unwrap();
        let mut reader = encoded.as_slice();
        let parsed: SignalRequest = reader.decode_one().await.unwrap();

        assert_eq!(parsed.signal_name, "INT");
    }

    // -------------------------------------------------------------------
    // Test 4: allocate_pty succeeds and returns valid FDs
    // -------------------------------------------------------------------

    #[test]
    fn allocate_pty_succeeds() {
        let request = PtyRequest {
            term_type: "xterm".into(),
            width_cols: 80,
            height_rows: 24,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
        };

        let pair = allocate_pty(&request).unwrap();

        // Both FDs should be valid (non-negative).
        assert!(pair.master.as_raw_fd() >= 0);
        assert!(pair.slave.as_raw_fd() >= 0);
        // Master and slave should be different FDs.
        assert_ne!(pair.master.as_raw_fd(), pair.slave.as_raw_fd());
    }

    // -------------------------------------------------------------------
    // Test 5: set_window_size on allocated PTY
    // -------------------------------------------------------------------

    #[test]
    fn set_window_size_on_allocated_pty() {
        let request = PtyRequest {
            term_type: "vt100".into(),
            width_cols: 80,
            height_rows: 24,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
        };

        let pair = allocate_pty(&request).unwrap();

        let resize = WindowChangeRequest {
            width_cols: 120,
            height_rows: 40,
            width_px: 960,
            height_px: 800,
        };

        // set_window_size should succeed on a valid PTY master FD.
        set_window_size(pair.master.as_raw_fd(), &resize).unwrap();

        // Verify by reading back the winsize via TIOCGWINSZ.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { tiocgwinsz(pair.master.as_raw_fd(), &mut ws as *mut libc::winsize) }.unwrap();
        assert_eq!(ws.ws_col, 120);
        assert_eq!(ws.ws_row, 40);
        assert_eq!(ws.ws_xpixel, 960);
        assert_eq!(ws.ws_ypixel, 800);
    }

    // -------------------------------------------------------------------
    // Test 6: pty request codec with empty terminal modes
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pty_request_codec_empty_terminal_modes() {
        let original = PtyRequest {
            term_type: "dumb".into(),
            width_cols: 40,
            height_rows: 10,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
        };

        let mut encoded = Vec::new();
        encoded.encode_one(&original).await.unwrap();
        let mut reader = encoded.as_slice();
        let parsed: PtyRequest = reader.decode_one().await.unwrap();

        assert_eq!(parsed.term_type, "dumb");
        assert_eq!(parsed.width_cols, 40);
        assert_eq!(parsed.height_rows, 10);
        assert!(parsed.terminal_modes.is_empty());
    }

    // -------------------------------------------------------------------
    // Test 7: signal codec with various signal names
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn signal_codec_various_names() {
        for name in &["TERM", "KILL", "HUP", "USR1", "USR2", "QUIT"] {
            let original = SignalRequest {
                signal_name: name.to_string(),
            };
            let mut encoded = Vec::new();
            encoded.encode_one(&original).await.unwrap();
            let mut reader = encoded.as_slice();
            let parsed: SignalRequest = reader.decode_one().await.unwrap();
            assert_eq!(parsed.signal_name, *name);
        }
    }

    // -------------------------------------------------------------------
    // Test 8: allocate_pty with initial size is set correctly
    // -------------------------------------------------------------------

    #[test]
    fn allocate_pty_initial_size() {
        let request = PtyRequest {
            term_type: "xterm".into(),
            width_cols: 132,
            height_rows: 43,
            width_px: 1056,
            height_px: 688,
            terminal_modes: vec![],
        };

        let pair = allocate_pty(&request).unwrap();

        // Verify the initial size was set via TIOCGWINSZ on the master.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { tiocgwinsz(pair.master.as_raw_fd(), &mut ws as *mut libc::winsize) }.unwrap();
        assert_eq!(ws.ws_col, 132);
        assert_eq!(ws.ws_row, 43);
        assert_eq!(ws.ws_xpixel, 1056);
        assert_eq!(ws.ws_ypixel, 688);
    }

    // -------------------------------------------------------------------
    // checked_winsize overflow tests
    // -------------------------------------------------------------------

    #[test]
    fn checked_winsize_overflow_width_cols() {
        let result = checked_winsize(u16::MAX as u32 + 1, 24, 0, 0);
        let err = result.unwrap_err();
        assert_eq!(err.field, "width_cols");
        assert_eq!(err.value, u16::MAX as u32 + 1);
    }

    #[test]
    fn checked_winsize_overflow_height_rows() {
        let result = checked_winsize(80, u16::MAX as u32 + 1, 0, 0);
        let err = result.unwrap_err();
        assert_eq!(err.field, "height_rows");
        assert_eq!(err.value, u16::MAX as u32 + 1);
    }

    #[test]
    fn checked_winsize_overflow_pixel_width() {
        let result = checked_winsize(80, 24, u16::MAX as u32 + 1, 0);
        let err = result.unwrap_err();
        assert_eq!(err.field, "width_px");
        assert_eq!(err.value, u16::MAX as u32 + 1);
    }

    #[test]
    fn checked_winsize_overflow_pixel_height() {
        let result = checked_winsize(80, 24, 0, u16::MAX as u32 + 1);
        let err = result.unwrap_err();
        assert_eq!(err.field, "height_px");
        assert_eq!(err.value, u16::MAX as u32 + 1);
    }

    #[test]
    fn checked_winsize_all_in_range() {
        let ws = checked_winsize(
            u16::MAX as u32,
            u16::MAX as u32,
            u16::MAX as u32,
            u16::MAX as u32,
        ).unwrap();
        assert_eq!(ws.ws_col, u16::MAX);
        assert_eq!(ws.ws_row, u16::MAX);
        assert_eq!(ws.ws_xpixel, u16::MAX);
        assert_eq!(ws.ws_ypixel, u16::MAX);
    }

    #[test]
    fn allocate_pty_rejects_overflow() {
        let request = PtyRequest {
            term_type: "xterm".into(),
            width_cols: u16::MAX as u32 + 1,
            height_rows: 24,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
        };
        let err = allocate_pty(&request).unwrap_err();
        match err {
            PtyError::Dimension { source } => {
                assert_eq!(source.field, "width_cols");
                assert_eq!(source.value, u16::MAX as u32 + 1);
            }
            other => panic!("expected DimensionOverflow, got {other:?}"),
        }
    }

    #[test]
    fn set_window_size_rejects_overflow() {
        let pty_req = PtyRequest {
            term_type: "xterm".into(),
            width_cols: 80,
            height_rows: 24,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
        };
        let pair = allocate_pty(&pty_req).unwrap();

        let resize = WindowChangeRequest {
            width_cols: 80,
            height_rows: u16::MAX as u32 + 1,
            width_px: 0,
            height_px: 0,
        };
        let err = set_window_size(pair.master.as_raw_fd(), &resize).unwrap_err();
        match err {
            PtyError::Dimension { source } => {
                assert_eq!(source.field, "height_rows");
                assert_eq!(source.value, u16::MAX as u32 + 1);
            }
            other => panic!("expected DimensionOverflow, got {other:?}"),
        }
    }
}
