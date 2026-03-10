//! PTY allocation and terminal handling for SSH3 sessions.
//!
//! Handles `pty-req`, `window-change`, and `signal` ChannelRequest types
//! per RFC 4254 Sections 6.2, 6.7.

use std::io;
use std::os::fd::{OwnedFd, RawFd};

use genmeta_ssh3_proto::codec::SshString;
use h3x::{codec::DecodeExt, varint::VarInt};
use nix::pty::{openpty, Winsize};

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
// Request parsing
// ---------------------------------------------------------------------------

/// Decode a pty-req request from `request_data` bytes.
///
/// Fields (RFC 4254 §6.2):
/// - `SshString`: TERM environment variable value
/// - `VarInt` (u32): terminal width, characters
/// - `VarInt` (u32): terminal height, rows
/// - `VarInt` (u32): terminal width, pixels
/// - `VarInt` (u32): terminal height, pixels
/// - varint-length-prefixed bytes: encoded terminal modes
pub async fn parse_pty_request(request_data: &[u8]) -> io::Result<PtyRequest> {
    let mut reader = request_data;

    let term_type = SshString::decode(&mut reader).await?;

    let width_cols: VarInt = reader.decode_one().await?;
    let height_rows: VarInt = reader.decode_one().await?;
    let width_px: VarInt = reader.decode_one().await?;
    let height_px: VarInt = reader.decode_one().await?;

    // Terminal modes: varint length prefix + raw bytes (same encoding as SshBytes).
    let modes_len: VarInt = reader.decode_one().await?;
    let modes_len = modes_len.into_inner() as usize;
    let mut terminal_modes = vec![0u8; modes_len];
    tokio::io::AsyncReadExt::read_exact(&mut reader, &mut terminal_modes).await?;

    Ok(PtyRequest {
        term_type: term_type.0,
        width_cols: width_cols.into_inner() as u32,
        height_rows: height_rows.into_inner() as u32,
        width_px: width_px.into_inner() as u32,
        height_px: height_px.into_inner() as u32,
        terminal_modes,
    })
}

/// Decode a window-change request from `request_data` bytes.
///
/// Fields (RFC 4254 §6.7):
/// - `VarInt` (u32): terminal width, columns
/// - `VarInt` (u32): terminal height, rows
/// - `VarInt` (u32): terminal width, pixels
/// - `VarInt` (u32): terminal height, pixels
pub async fn parse_window_change(request_data: &[u8]) -> io::Result<WindowChangeRequest> {
    let mut reader = request_data;

    let width_cols: VarInt = reader.decode_one().await?;
    let height_rows: VarInt = reader.decode_one().await?;
    let width_px: VarInt = reader.decode_one().await?;
    let height_px: VarInt = reader.decode_one().await?;

    Ok(WindowChangeRequest {
        width_cols: width_cols.into_inner() as u32,
        height_rows: height_rows.into_inner() as u32,
        width_px: width_px.into_inner() as u32,
        height_px: height_px.into_inner() as u32,
    })
}

/// Decode a signal request from `request_data` bytes.
///
/// Fields (RFC 4254 §6.9):
/// - `SshString`: signal name (without "SIG" prefix, e.g., "INT", "TERM", "KILL")
pub async fn parse_signal(request_data: &[u8]) -> io::Result<SignalRequest> {
    let mut reader = request_data;
    let signal_name = SshString::decode(&mut reader).await?;
    Ok(SignalRequest {
        signal_name: signal_name.0,
    })
}

// ---------------------------------------------------------------------------
// PTY allocation and terminal size
// ---------------------------------------------------------------------------

/// Allocate a new PTY pair with the requested terminal size.
///
/// Uses `nix::pty::openpty` to create the master/slave pair, then sets the
/// terminal size via ioctl `TIOCSWINSZ`.
pub fn allocate_pty(request: &PtyRequest) -> io::Result<PtyPair> {
    let winsize = Winsize {
        ws_row: request.height_rows as u16,
        ws_col: request.width_cols as u16,
        ws_xpixel: request.width_px as u16,
        ws_ypixel: request.height_px as u16,
    };

    let pty_result = openpty(Some(&winsize), None)
        .map_err(io::Error::other)?;

    Ok(PtyPair {
        master: pty_result.master,
        slave: pty_result.slave,
    })
}

/// Update the terminal size of an existing PTY via ioctl `TIOCSWINSZ`.
pub fn set_window_size(master_fd: RawFd, request: &WindowChangeRequest) -> io::Result<()> {
    let winsize = libc::winsize {
        ws_row: request.height_rows as u16,
        ws_col: request.width_cols as u16,
        ws_xpixel: request.width_px as u16,
        ws_ypixel: request.height_px as u16,
    };

    let ret = unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &winsize as *const _) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Encoding helpers (for test roundtrips)
// ---------------------------------------------------------------------------

/// Encode a PtyRequest into wire bytes for testing.
#[cfg(test)]
async fn encode_pty_request(req: &PtyRequest) -> io::Result<Vec<u8>> {
    use h3x::codec::EncodeExt;
    use tokio::io::AsyncWriteExt;

    let mut buf = Vec::new();
    SshString(req.term_type.clone()).encode(&mut buf).await?;

    let width_cols = VarInt::try_from(req.width_cols as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(width_cols).await?;

    let height_rows = VarInt::try_from(req.height_rows as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(height_rows).await?;

    let width_px = VarInt::try_from(req.width_px as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(width_px).await?;

    let height_px = VarInt::try_from(req.height_px as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(height_px).await?;

    // Terminal modes: varint length prefix + raw bytes.
    let modes_len = VarInt::try_from(req.terminal_modes.len() as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(modes_len).await?;
    buf.write_all(&req.terminal_modes).await?;

    Ok(buf)
}

/// Encode a WindowChangeRequest into wire bytes for testing.
#[cfg(test)]
async fn encode_window_change(req: &WindowChangeRequest) -> io::Result<Vec<u8>> {
    use h3x::codec::EncodeExt;

    let mut buf = Vec::new();

    let width_cols = VarInt::try_from(req.width_cols as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(width_cols).await?;

    let height_rows = VarInt::try_from(req.height_rows as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(height_rows).await?;

    let width_px = VarInt::try_from(req.width_px as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(width_px).await?;

    let height_px = VarInt::try_from(req.height_px as u64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    buf.encode_one(height_px).await?;

    Ok(buf)
}

/// Encode a SignalRequest into wire bytes for testing.
#[cfg(test)]
async fn encode_signal(req: &SignalRequest) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    SshString(req.signal_name.clone()).encode(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

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

        let encoded = encode_pty_request(&original).await.unwrap();
        let parsed = parse_pty_request(&encoded).await.unwrap();

        assert_eq!(parsed.term_type, original.term_type);
        assert_eq!(parsed.width_cols, original.width_cols);
        assert_eq!(parsed.height_rows, original.height_rows);
        assert_eq!(parsed.width_px, original.width_px);
        assert_eq!(parsed.height_px, original.height_px);
        assert_eq!(parsed.terminal_modes, original.terminal_modes);
    }

    // -------------------------------------------------------------------
    // Test 2: parse_window_change roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_window_change_roundtrip() {
        let original = WindowChangeRequest {
            width_cols: 120,
            height_rows: 40,
            width_px: 960,
            height_px: 800,
        };

        let encoded = encode_window_change(&original).await.unwrap();
        let parsed = parse_window_change(&encoded).await.unwrap();

        assert_eq!(parsed.width_cols, original.width_cols);
        assert_eq!(parsed.height_rows, original.height_rows);
        assert_eq!(parsed.width_px, original.width_px);
        assert_eq!(parsed.height_px, original.height_px);
    }

    // -------------------------------------------------------------------
    // Test 3: parse_signal roundtrip
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_signal_roundtrip() {
        let original = SignalRequest {
            signal_name: "INT".into(),
        };

        let encoded = encode_signal(&original).await.unwrap();
        let parsed = parse_signal(&encoded).await.unwrap();

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
        let ret = unsafe {
            libc::ioctl(pair.master.as_raw_fd(), libc::TIOCGWINSZ, &mut ws as *mut _)
        };
        assert_eq!(ret, 0);
        assert_eq!(ws.ws_col, 120);
        assert_eq!(ws.ws_row, 40);
        assert_eq!(ws.ws_xpixel, 960);
        assert_eq!(ws.ws_ypixel, 800);
    }

    // -------------------------------------------------------------------
    // Test 6: parse_pty_request with empty terminal modes
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_pty_request_empty_terminal_modes() {
        let original = PtyRequest {
            term_type: "dumb".into(),
            width_cols: 40,
            height_rows: 10,
            width_px: 0,
            height_px: 0,
            terminal_modes: vec![],
        };

        let encoded = encode_pty_request(&original).await.unwrap();
        let parsed = parse_pty_request(&encoded).await.unwrap();

        assert_eq!(parsed.term_type, "dumb");
        assert_eq!(parsed.width_cols, 40);
        assert_eq!(parsed.height_rows, 10);
        assert!(parsed.terminal_modes.is_empty());
    }

    // -------------------------------------------------------------------
    // Test 7: parse_signal with various signal names
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn parse_signal_various_names() {
        for name in &["TERM", "KILL", "HUP", "USR1", "USR2", "QUIT"] {
            let original = SignalRequest {
                signal_name: name.to_string(),
            };
            let encoded = encode_signal(&original).await.unwrap();
            let parsed = parse_signal(&encoded).await.unwrap();
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
        let ret = unsafe {
            libc::ioctl(pair.master.as_raw_fd(), libc::TIOCGWINSZ, &mut ws as *mut _)
        };
        assert_eq!(ret, 0);
        assert_eq!(ws.ws_col, 132);
        assert_eq!(ws.ws_row, 43);
        assert_eq!(ws.ws_xpixel, 1056);
        assert_eq!(ws.ws_ypixel, 688);
    }
}
