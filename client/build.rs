/// Build script: require environment variables at compile time.
/// This ensures the server URL and public key are baked into the binary.

fn main() {
    // LICENSE_SERVER_URL must be set at build time
    let server_url = std::env::var("LICENSE_SERVER_URL")
        .unwrap_or_else(|_| "https://YOUR-SERVER-DOMAIN".to_string());
    println!("cargo:rustc-env=LICENSE_SERVER_URL={}", server_url);

    // SERVER_PUBLIC_KEY_HEX must be set at build time (32-byte Ed25519 public key as hex)
    let pub_key = std::env::var("SERVER_PUBLIC_KEY_HEX")
        .unwrap_or_else(|_| {
            eprintln!("WARNING: SERVER_PUBLIC_KEY_HEX not set. Using placeholder.");
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });
    println!("cargo:rustc-env=SERVER_PUBLIC_KEY_HEX={}", pub_key);

    // Rerun if these env vars change
    println!("cargo:rerun-if-env-changed=LICENSE_SERVER_URL");
    println!("cargo:rerun-if-env-changed=SERVER_PUBLIC_KEY_HEX");
}
