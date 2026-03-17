//! PTY allocation and terminal handling for SSH3 sessions.
//!
//! Handles `pty-req`, `window-change`, and `signal` ChannelRequest types
//! per RFC 4254 Sections 6.2, 6.7.

use std::os::fd::{OwnedFd, RawFd};
use std::pin::pin;

use genmeta_ssh3_proto::codec::SshString;
use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::VarInt,
};
use nix::pty::{openpty, Winsize};
use snafu::{ResultExt, Snafu};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

nix::ioctl_write_ptr_bad!(tiocswinsz, libc::TIOCSWINSZ, libc::winsize);
#[cfg(test)]
nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);

// ---------------------------------------------------------------------------
// Parsed request types
// ---------------------------------------------------------------------------

/// Parsed pty-req request (RFC 4254 §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRequest {
    /// TERM environment variable value (e.g., "xterm").
    pub term_type: String,
    /// Terminal width in characters/columns.
    pub width_cols: u32,
    /// Terminal height in rows.
    pub height_rows: u32,
    /// Terminal width in pixels.
    pub width_px: u32,
    /// Terminal height in pixels.
    pub height_px: u32,
    /// Encoded terminal modes (opaque bytes).
    pub terminal_modes: Vec<u8>,
}

/// Parsed window-change request (RFC 4254 §6.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowChangeRequest {
    /// Terminal width in columns.
    pub width_cols: u32,
    /// Terminal height in rows.
    pub height_rows: u32,
    /// Terminal width in pixels.
    pub width_px: u32,
    /// Terminal height in pixels.
    pub height_px: u32,
}

/// Parsed signal request (RFC 4254 §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalRequest {
    /// Signal name without "SIG" prefix (e.g., "INT", "TERM", "KILL").
    pub signal_name: String,
}

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

/// Errors that can occur when encoding/decoding PTY-related request structs.
#[derive(Debug, Snafu)]
pub enum PtyCodecError {
    /// An I/O error occurred during encoding or decoding.
    #[snafu(display("PTY codec I/O error: {source}"), context(false))]
    Io { source: io::Error },

    /// A VarInt value could not be converted for encoding.
    #[snafu(display("PTY codec VarInt conversion error: {source}"))]
    VarIntConversion { source: h3x::varint::err::Overflow },
}

// ---------------------------------------------------------------------------
// DecodeFrom / EncodeInto implementations
// ---------------------------------------------------------------------------

/// Decode a pty-req request from a stream (RFC 4254 §6.2).
///
/// Fields:
/// - `SshString`: TERM environment variable value
/// - `VarInt` (u32): terminal width, characters
/// - `VarInt` (u32): terminal height, rows
/// - `VarInt` (u32): terminal width, pixels
/// - `VarInt` (u32): terminal height, pixels
/// - varint-length-prefixed bytes: encoded terminal modes
impl<S: AsyncRead + Send> DecodeFrom<S> for PtyRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);

        let term_type: SshString = stream.decode_one().await?;
        let width_cols: VarInt = stream.decode_one().await?;
        let height_rows: VarInt = stream.decode_one().await?;
        let width_px: VarInt = stream.decode_one().await?;
        let height_px: VarInt = stream.decode_one().await?;

        // Terminal modes: varint length prefix + raw bytes (same encoding as SshBytes).
        let modes_len: VarInt = stream.decode_one().await?;
        let modes_len = modes_len.into_inner() as usize;
        let mut terminal_modes = vec![0u8; modes_len];
        stream.read_exact(&mut terminal_modes).await?;

        Ok(PtyRequest {
            term_type: term_type.0,
            width_cols: width_cols.into_inner() as u32,
            height_rows: height_rows.into_inner() as u32,
            width_px: width_px.into_inner() as u32,
            height_px: height_px.into_inner() as u32,
            terminal_modes,
        })
    }
}

/// Encode a pty-req request into a stream (RFC 4254 §6.2).
impl<S: AsyncWrite + Send> EncodeInto<S> for &PtyRequest {
    type Output = ();
    type Error = PtyCodecError;

    async fn encode_into(self, stream: S) -> Result<(), PtyCodecError> {
        let mut stream = pin!(stream);

        stream
            .encode_one(SshString(self.term_type.clone()))
            .await?;

        stream
            .encode_one(VarInt::try_from(self.width_cols as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream
            .encode_one(VarInt::try_from(self.height_rows as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream
            .encode_one(VarInt::try_from(self.width_px as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream
            .encode_one(VarInt::try_from(self.height_px as u64).context(VarIntConversionSnafu)?)
            .await?;

        // Terminal modes: varint length prefix + raw bytes.
        stream
            .encode_one(VarInt::try_from(self.terminal_modes.len() as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream.write_all(&self.terminal_modes).await?;

        Ok(())
    }
}

/// Decode a window-change request from a stream (RFC 4254 §6.7).
///
/// Fields:
/// - `VarInt` (u32): terminal width, columns
/// - `VarInt` (u32): terminal height, rows
/// - `VarInt` (u32): terminal width, pixels
/// - `VarInt` (u32): terminal height, pixels
impl<S: AsyncRead + Send> DecodeFrom<S> for WindowChangeRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);

        let width_cols: VarInt = stream.decode_one().await?;
        let height_rows: VarInt = stream.decode_one().await?;
        let width_px: VarInt = stream.decode_one().await?;
        let height_px: VarInt = stream.decode_one().await?;

        Ok(WindowChangeRequest {
            width_cols: width_cols.into_inner() as u32,
            height_rows: height_rows.into_inner() as u32,
            width_px: width_px.into_inner() as u32,
            height_px: height_px.into_inner() as u32,
        })
    }
}

/// Encode a window-change request into a stream (RFC 4254 §6.7).
impl<S: AsyncWrite + Send> EncodeInto<S> for &WindowChangeRequest {
    type Output = ();
    type Error = PtyCodecError;

    async fn encode_into(self, stream: S) -> Result<(), PtyCodecError> {
        let mut stream = pin!(stream);

        stream
            .encode_one(VarInt::try_from(self.width_cols as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream
            .encode_one(VarInt::try_from(self.height_rows as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream
            .encode_one(VarInt::try_from(self.width_px as u64).context(VarIntConversionSnafu)?)
            .await?;
        stream
            .encode_one(VarInt::try_from(self.height_px as u64).context(VarIntConversionSnafu)?)
            .await?;

        Ok(())
    }
}

/// Decode a signal request from a stream (RFC 4254 §6.9).
///
/// Fields:
/// - `SshString`: signal name (without "SIG" prefix, e.g., "INT", "TERM", "KILL")
impl<S: AsyncRead + Send> DecodeFrom<S> for SignalRequest {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);
        let signal_name: SshString = stream.decode_one().await?;
        Ok(SignalRequest {
            signal_name: signal_name.0,
        })
    }
}

/// Encode a signal request into a stream (RFC 4254 §6.9).
impl<S: AsyncWrite + Send> EncodeInto<S> for &SignalRequest {
    type Output = ();
    type Error = PtyCodecError;

    async fn encode_into(self, stream: S) -> Result<(), PtyCodecError> {
        let mut stream = pin!(stream);
        stream
            .encode_one(SshString(self.signal_name.clone()))
            .await?;
        Ok(())
    }
}

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
    #[snafu(display("PTY OS error: {source}"))]
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
    let ws = validate_pty_dimensions(request).map_err(|source| PtyError::Dimension { source })?;
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
        validate_window_change_dimensions(request).map_err(|source| PtyError::Dimension { source })?;

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
