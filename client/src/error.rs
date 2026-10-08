use std::fmt;

#[derive(Debug)]
pub enum LicenseError {
    HwidError(String),
    NetworkError(String),
    ServerError(u16, String),
    CryptoError(String),
    ParseError(String),
    LicenseRevoked(String),
    SessionExpired,
}

impl fmt::Display for LicenseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LicenseError::HwidError(e)        => write!(f, "HWID error: {}", e),
            LicenseError::NetworkError(e)     => write!(f, "Network error: {}", e),
            LicenseError::ServerError(c, e)   => write!(f, "Server error {}: {}", c, e),
            LicenseError::CryptoError(e)      => write!(f, "Crypto error: {}", e),
            LicenseError::ParseError(e)       => write!(f, "Parse error: {}", e),
            LicenseError::LicenseRevoked(r)   => write!(f, "License revoked: {}", r),
            LicenseError::SessionExpired      => write!(f, "Session expired"),
        }
    }
}

impl std::error::Error for LicenseError {}
