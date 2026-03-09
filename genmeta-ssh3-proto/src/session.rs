use serde::{Deserialize, Serialize};

/// Authentication credentials extracted from HTTP Authorization header.
/// MVP: only Password (Basic auth) supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthCredential {
    /// Password from HTTP Basic authentication (base64-decoded)
    Password(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_serde_roundtrip() {
        let cred = AuthCredential::Password("secret123".to_string());
        let json = serde_json::to_string(&cred).unwrap();
        let decoded: AuthCredential = serde_json::from_str(&json).unwrap();
        match decoded {
            AuthCredential::Password(p) => assert_eq!(p, "secret123"),
        }
    }
}
