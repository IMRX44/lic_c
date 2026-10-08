/// Hardware ID generation.
/// Combines multiple hardware sources into a stable, hashed identifier.
/// The raw HWID is never sent to the server — only SHA-256(raw_hwid + server_salt).

use sha2::{Sha256, Digest};

#[cfg(target_os = "linux")]
pub fn get_raw_hwid() -> Result<String, String> {
    // Primary: machine-id (stable across reboots, unique per install)
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Secondary: CPU info (model name from /proc/cpuinfo)
    let cpu_info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu_model = cpu_info
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    // Tertiary: /sys/class/dmi/id/product_uuid (if available)
    let product_uuid = std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if machine_id.is_empty() && product_uuid.is_empty() {
        return Err("Cannot determine hardware ID".to_string());
    }

    Ok(format!("{}|{}|{}", machine_id, cpu_model, product_uuid))
}

#[cfg(target_os = "windows")]
pub fn get_raw_hwid() -> Result<String, String> {
    use winreg::enums::*;
    use winreg::RegKey;

    // Primary: MachineGuid from registry
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let machine_guid = hklm
        .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
        .and_then(|k| k.get_value::<String, _>("MachineGuid"))
        .unwrap_or_default();

    // Secondary: ComputerName
    let computer_name = hklm
        .open_subkey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName")
        .and_then(|k| k.get_value::<String, _>("ComputerName"))
        .unwrap_or_default();

    if machine_guid.is_empty() {
        return Err("Cannot determine hardware ID".to_string());
    }

    Ok(format!("{}|{}", machine_guid, computer_name))
}

/// Hash the raw HWID with a salt so the server never sees the raw identifier.
/// salt is provided by the server or derived from license_key.
pub fn compute_hwid_hash(raw_hwid: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_hwid.as_bytes());
    hasher.update(b":");
    hasher.update(salt.as_bytes());
    hex::encode(hasher.finalize())
}

/// Derive the AES wrapping key used to decrypt the session key.
/// Must match the server's encrypt_session_key derivation.
pub fn derive_wrapping_key(hwid_hash: &str, license_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", hwid_hash, license_id).as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hwid_is_deterministic() {
        let h1 = get_raw_hwid();
        let h2 = get_raw_hwid();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = compute_hwid_hash("test-hwid", "salt");
        let h2 = compute_hwid_hash("test-hwid", "salt");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_salts_give_different_hashes() {
        let h1 = compute_hwid_hash("test-hwid", "salt1");
        let h2 = compute_hwid_hash("test-hwid", "salt2");
        assert_ne!(h1, h2);
    }
}
