/*!
# liclient — SDK کلاینت لایسنس

## نحوه استفاده

```rust
use liclient::{LicenseGuard, LicenseConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let guard = LicenseGuard::new(LicenseConfig {
        license_key: "XXXX-XXXX-XXXX-XXXX-XXXX".to_string(),
        product_slug: "my-product".to_string(),
        client_version: "1.0.0".to_string(),
    })
    .on_revoke(move |msg| {
        eprintln!("⚠ {}", msg);
        // 10-second countdown then exit
        std::thread::sleep(std::time::Duration::from_secs(10));
        running_clone.store(false, Ordering::SeqCst);
    })
    .activate()
    .await
    .expect("فعال‌سازی لایسنس ناموفق بود");

    // Your application runs here
    // guard keeps the heartbeat + websocket running
    // When dropped, connections are closed
    while running.load(Ordering::SeqCst) {
        // ... your app loop ...
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
```
*/

pub mod crypto;
pub mod error;
pub mod heartbeat;
pub mod hwid;
pub mod license;
pub mod websocket;

use std::sync::Arc;
use tokio::sync::{Mutex, watch};

pub use error::LicenseError;
pub use license::LicenseSession;

/// Configuration for license activation.
pub struct LicenseConfig {
    pub license_key: String,
    pub product_slug: String,
    pub client_version: String,
}

/// Builder for activating and guarding a license session.
pub struct LicenseGuard {
    config: LicenseConfig,
    on_revoke_fn: Option<Box<dyn Fn(String) + Send + 'static>>,
}

impl LicenseGuard {
    pub fn new(config: LicenseConfig) -> Self {
        Self { config, on_revoke_fn: None }
    }

    /// Register a callback invoked when the license is revoked or expires.
    /// The callback receives a human-readable message.
    /// **You must initiate application shutdown inside this callback** (e.g., set an atomic flag).
    pub fn on_revoke(mut self, f: impl Fn(String) + Send + 'static) -> Self {
        self.on_revoke_fn = Some(Box::new(f));
        self
    }

    /// Activate the license and start heartbeat + WebSocket background tasks.
    pub async fn activate(self) -> Result<ActiveGuard, LicenseError> {
        let session = license::activate(
            &self.config.license_key,
            &self.config.product_slug,
            &self.config.client_version,
        )
        .await?;

        let session_token = session.token.clone();
        let session = Arc::new(Mutex::new(session));
        let (stop_tx, stop_rx) = watch::channel(false);

        let on_revoke: Arc<dyn Fn(String) + Send + Sync + 'static> = match self.on_revoke_fn {
            Some(f) => Arc::new(f),
            None => Arc::new(|msg: String| {
                eprintln!("License revoked: {}", msg);
                std::thread::sleep(std::time::Duration::from_secs(10));
                std::process::exit(1);
            }),
        };

        // Start heartbeat loop
        let on_revoke_hb = on_revoke.clone();
        let hb_stop = heartbeat::start_heartbeat_loop(session.clone(), move |msg| {
            (on_revoke_hb)(msg);
        });

        // Start WebSocket listener
        let on_revoke_ws = on_revoke.clone();
        websocket::start_ws_listener(session_token, move |action, message| {
            if action == "revoke" {
                (on_revoke_ws)(message);
            }
        }, stop_rx.clone());

        Ok(ActiveGuard {
            _session: session,
            _stop: hb_stop,
            _stop_ws: stop_rx,
        })
    }
}

/// Keeps background tasks alive. Drop to stop heartbeat and WebSocket.
pub struct ActiveGuard {
    _session: Arc<Mutex<LicenseSession>>,
    _stop: heartbeat::ShutdownSender,
    _stop_ws: watch::Receiver<bool>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let _ = self._stop.send(true);
    }
}
