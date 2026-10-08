/// License activation and heartbeat logic.

use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::hwid::{compute_hwid_hash, derive_wrapping_key, get_raw_hwid};
use crate::crypto::{decrypt_session_key, verify_session_token, SessionClaims, SessionKey};
use crate::error::LicenseError;

/// Server URL — pinned at compile time, cannot be overridden at runtime.
pub const SERVER_URL: &str = env!("LICENSE_SERVER_URL");

/// HWID salt — derived from license key in practice.
fn hwid_salt(license_key: &str) -> String {
    format!("hwid-salt-{}", &license_key[..8.min(license_key.len())])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActivateRequest {
    license_key: String,
    hwid_hash: String,
    platform: String,
    product_slug: String,
    client_version: String,
    nonce: String,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct ActivateResponse {
    session_token: String,
    session_key_hex: String,
    expires_at: u64,
    server_public_key: String,
    heartbeat_interval: u64,
}

#[derive(Debug, Serialize)]
struct HeartbeatRequest {
    session_token: String,
    hwid_hash: String,
    nonce: String,
    timestamp: u64,
    integrity_report: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub session_key_hex: String,
    pub expires_at: u64,
    pub next_heartbeat: u64,
    pub message: Option<String>,
    pub action: Option<String>,
}

/// Active license session.
pub struct LicenseSession {
    pub token: String,
    pub hwid_hash: String,
    pub license_id: String,
    pub product_slug: String,
    pub session_key: SessionKey,    // zeroized on drop
    pub expires_at: u64,
    pub next_heartbeat: u64,
    pub heartbeat_interval: u64,
}

/// Activate a license. Returns a LicenseSession on success.
pub async fn activate(
    license_key: &str,
    product_slug: &str,
    client_version: &str,
) -> Result<LicenseSession, LicenseError> {
    let raw_hwid = get_raw_hwid().map_err(LicenseError::HwidError)?;
    let salt = hwid_salt(license_key);
    let hwid_hash = compute_hwid_hash(&raw_hwid, &salt);

    let now = unix_now();
    let req = ActivateRequest {
        license_key: license_key.to_uppercase(),
        hwid_hash: hwid_hash.clone(),
        platform: current_platform(),
        product_slug: product_slug.to_string(),
        client_version: client_version.to_string(),
        nonce: Uuid::new_v4().to_string(),
        timestamp: now,
    };

    let client = build_http_client()?;
    let url = format!("{}/api/v1/activate", SERVER_URL);
    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| LicenseError::NetworkError(e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let detail = body["detail"].as_str().unwrap_or("Server error").to_string();
        return Err(LicenseError::ServerError(status, detail));
    }

    let data: ActivateResponse = resp.json().await.map_err(|e| LicenseError::ParseError(e.to_string()))?;

    // Verify token signature
    let claims = verify_session_token(&data.session_token)
        .map_err(LicenseError::CryptoError)?;

    // Verify server public key matches pinned key
    #[cfg(not(test))]
    {
        use crate::crypto::PINNED_SERVER_PUBLIC_KEY_HEX;
        if data.server_public_key != PINNED_SERVER_PUBLIC_KEY_HEX {
            return Err(LicenseError::CryptoError("Server public key mismatch (possible MITM)".to_string()));
        }
    }

    // Decrypt session key using HWID-derived wrapping key
    let wrapping_key = derive_wrapping_key(&hwid_hash, &claims.license_id);
    let session_key_bytes = decrypt_session_key(&data.session_key_hex, &wrapping_key)
        .map_err(LicenseError::CryptoError)?;

    let heartbeat_interval = data.heartbeat_interval.max(30).min(300);

    Ok(LicenseSession {
        token: data.session_token,
        hwid_hash,
        license_id: claims.license_id,
        product_slug: claims.product_slug,
        session_key: SessionKey(session_key_bytes),
        expires_at: data.expires_at,
        next_heartbeat: now + heartbeat_interval,
        heartbeat_interval,
    })
}

/// Send heartbeat to renew session key.
pub async fn heartbeat(session: &mut LicenseSession) -> Result<HeartbeatResponse, LicenseError> {
    let now = unix_now();
    let req = HeartbeatRequest {
        session_token: session.token.clone(),
        hwid_hash: session.hwid_hash.clone(),
        nonce: Uuid::new_v4().to_string(),
        timestamp: now,
        integrity_report: collect_integrity_report(),
    };

    let client = build_http_client()?;
    let url = format!("{}/api/v1/heartbeat", SERVER_URL);
    let resp = client
        .post(&url)
        .json(&req)
        .send()
        .await
        .map_err(|e| LicenseError::NetworkError(e.to_string()))?;

    if resp.status().as_u16() == 403 {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let detail = body["detail"].as_str().unwrap_or("").to_string();
        return Err(LicenseError::LicenseRevoked(detail));
    }

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(LicenseError::ServerError(status, "Heartbeat failed".to_string()));
    }

    let data: HeartbeatResponse = resp.json().await.map_err(|e| LicenseError::ParseError(e.to_string()))?;

    // Renew session key
    let wrapping_key = derive_wrapping_key(&session.hwid_hash, &session.license_id);
    let new_key = decrypt_session_key(&data.session_key_hex, &wrapping_key)
        .map_err(LicenseError::CryptoError)?;

    session.session_key = SessionKey(new_key);
    session.expires_at = data.expires_at;
    session.next_heartbeat = data.next_heartbeat;

    Ok(data)
}

/// Collect basic integrity signals to send in heartbeat.
/// Non-invasive checks that help detect unusual environments.
fn collect_integrity_report() -> Option<serde_json::Value> {
    #[cfg(target_os = "linux")]
    {
        let mut anomalies = vec![];
        // Check if running under ptrace (basic check)
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            if let Some(line) = status.lines().find(|l| l.starts_with("TracerPid:")) {
                if let Some(pid) = line.split(':').nth(1).map(|s| s.trim()) {
                    if pid != "0" {
                        anomalies.push("debugger_attached");
                    }
                }
            }
        }
        if !anomalies.is_empty() {
            return Some(serde_json::json!({ "anomalies": anomalies }));
        }
    }
    None
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn current_platform() -> String {
    #[cfg(target_os = "windows")] { "windows".to_string() }
    #[cfg(target_os = "linux")]   { "linux".to_string() }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))] { "unknown".to_string() }
}

fn build_http_client() -> Result<reqwest::Client, LicenseError> {
    reqwest::Client::builder()
        // Enforce TLS - no fallback to HTTP
        .https_only(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| LicenseError::NetworkError(e.to_string()))
}
