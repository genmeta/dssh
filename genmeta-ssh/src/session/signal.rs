//! SSH signal name mapping per RFC 4254 Section 6.10.
//!
//! Provides conversion between SSH signal name strings (e.g., "INT", "TERM")
//! and Unix signal numbers.

use nix::sys::signal::Signal;

/// Map an SSH signal name (without "SIG" prefix) to a Unix signal.
///
/// Covers all signal names defined in RFC 4254 Section 6.10 plus common
/// extensions.
pub fn from_ssh_name(name: &str) -> Option<Signal> {
    match name {
        // RFC 4254 Section 6.10
        "ABRT" => Some(Signal::SIGABRT),
        "ALRM" => Some(Signal::SIGALRM),
        "FPE" => Some(Signal::SIGFPE),
        "HUP" => Some(Signal::SIGHUP),
        "ILL" => Some(Signal::SIGILL),
        "INT" => Some(Signal::SIGINT),
        "KILL" => Some(Signal::SIGKILL),
        "PIPE" => Some(Signal::SIGPIPE),
        "QUIT" => Some(Signal::SIGQUIT),
        "SEGV" => Some(Signal::SIGSEGV),
        "TERM" => Some(Signal::SIGTERM),
        "USR1" => Some(Signal::SIGUSR1),
        "USR2" => Some(Signal::SIGUSR2),
        // Common extensions
        "CONT" => Some(Signal::SIGCONT),
        "STOP" => Some(Signal::SIGSTOP),
        "TSTP" => Some(Signal::SIGTSTP),
        "TTIN" => Some(Signal::SIGTTIN),
        "TTOU" => Some(Signal::SIGTTOU),
        _ => None,
    }
}

/// Deliver a signal to a process or process group.
///
/// Attempts to signal the entire process group first (`killpg`). If the
/// process has no group (or is the group leader with pid == pgid), falls
/// back to signaling the process directly.
pub fn deliver(pid: nix::unistd::Pid, signal: Signal) -> Result<(), nix::Error> {
    match nix::sys::signal::killpg(pid, signal) {
        Ok(()) => Ok(()),
        Err(_) => nix::sys::signal::kill(pid, signal),
    }
}

/// Map a Unix signal number to its SSH name (without "SIG" prefix).
///
/// Returns `None` for unrecognized signal numbers. Uses a fallback format
/// `"signal-N@genmeta-ssh3"` for the caller to handle unknown signals.
pub fn to_ssh_name(signal_number: i32) -> Option<&'static str> {
    use nix::libc;
    match signal_number {
        libc::SIGABRT => Some("ABRT"),
        libc::SIGALRM => Some("ALRM"),
        libc::SIGFPE => Some("FPE"),
        libc::SIGHUP => Some("HUP"),
        libc::SIGILL => Some("ILL"),
        libc::SIGINT => Some("INT"),
        libc::SIGKILL => Some("KILL"),
        libc::SIGPIPE => Some("PIPE"),
        libc::SIGQUIT => Some("QUIT"),
        libc::SIGSEGV => Some("SEGV"),
        libc::SIGTERM => Some("TERM"),
        libc::SIGUSR1 => Some("USR1"),
        libc::SIGUSR2 => Some("USR2"),
        libc::SIGCONT => Some("CONT"),
        libc::SIGSTOP => Some("STOP"),
        libc::SIGTSTP => Some("TSTP"),
        libc::SIGTTIN => Some("TTIN"),
        libc::SIGTTOU => Some("TTOU"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4254_signals_all_mapped() {
        let rfc_signals = [
            "ABRT", "ALRM", "FPE", "HUP", "ILL", "INT", "KILL", "PIPE",
            "QUIT", "SEGV", "TERM", "USR1", "USR2",
        ];
        for name in rfc_signals {
            assert!(
                from_ssh_name(name).is_some(),
                "RFC 4254 signal {name} should be mapped"
            );
        }
    }

    #[test]
    fn unknown_signal_returns_none() {
        assert!(from_ssh_name("BOGUS").is_none());
        assert!(from_ssh_name("").is_none());
    }

    #[test]
    fn signal_number_roundtrip() {
        // from_ssh_name → signal → to_ssh_name should roundtrip
        for name in ["ABRT", "ALRM", "HUP", "INT", "KILL", "TERM", "USR1", "USR2"] {
            let sig = from_ssh_name(name).unwrap();
            let back = to_ssh_name(sig as i32).unwrap();
            assert_eq!(name, back, "roundtrip failed for {name}");
        }
    }
}
