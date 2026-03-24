//! POSIX privilege separation utilities.
//!
//! After PAM authentication, the session child process drops from root to
//! the target user before handling any SSH channels.  The sequence is:
//!
//! 1. `setgid(gid)` — switch primary group
//! 2. `initgroups(username, gid)` — load supplementary groups
//! 3. `setuid(uid)` — switch user (point of no return)
//!
//! The ordering is critical: `setuid` must come **last** because once the
//! process gives up root, it cannot change groups.

use std::ffi::CString;

use nix::unistd::{Gid, Uid};
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DropPrivilegesError {
    #[snafu(display("username contains interior NUL byte"))]
    InvalidUsername { source: std::ffi::NulError },

    #[snafu(display("setgid({gid}) failed"))]
    SetGid { gid: u32, source: nix::Error },

    #[snafu(display("initgroups({username}, {gid}) failed"))]
    InitGroups {
        username: String,
        gid: u32,
        source: nix::Error,
    },

    #[snafu(display("setuid({uid}) failed"))]
    SetUid { uid: u32, source: nix::Error },
}

/// Drop process privileges from root to the given user.
///
/// Must be called while running as root (UID 0). After this call the
/// process runs as `uid:gid` with the full supplementary group list
/// for `username`.
pub fn drop_privileges(uid: u32, gid: u32, username: &str) -> Result<(), DropPrivilegesError> {
    use drop_privileges_error::*;

    let c_username = CString::new(username).context(InvalidUsernameSnafu)?;
    let nix_gid = Gid::from_raw(gid);
    let nix_uid = Uid::from_raw(uid);

    nix::unistd::setgid(nix_gid).context(SetGidSnafu { gid })?;

    nix::unistd::initgroups(&c_username, nix_gid).context(InitGroupsSnafu { username, gid })?;

    nix::unistd::setuid(nix_uid).context(SetUidSnafu { uid })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_username_nul() {
        let result = drop_privileges(1000, 1000, "bad\0name");
        assert!(
            matches!(result, Err(DropPrivilegesError::InvalidUsername { .. })),
            "should reject NUL in username"
        );
    }

    #[test]
    fn drop_as_non_root_fails() {
        // Running tests as non-root: setgid should fail with EPERM.
        if nix::unistd::getuid().is_root() {
            return; // Skip if somehow running as root.
        }
        let result = drop_privileges(1000, 1000, "testuser");
        assert!(result.is_err(), "should fail when not root");
    }
}
