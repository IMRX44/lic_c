/// Background heartbeat task.
/// Runs in a separate async task; sends heartbeat to server before session key expires.
/// On revocation: calls the provided shutdown callback.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, watch};
use tokio::time::sleep;

use crate::license::{LicenseSession, heartbeat};
use crate::error::LicenseError;

pub type ShutdownSender = watch::Sender<bool>;
pub type ShutdownReceiver = watch::Receiver<bool>;

/// Start the heartbeat loop.
/// - `session`: shared mutable license session
/// - `on_revoke`: called with a message when license is revoked
/// - Returns a sender to stop the loop manually
pub fn start_heartbeat_loop(
    session: Arc<Mutex<LicenseSession>>,
    on_revoke: impl Fn(String) + Send + 'static,
) -> ShutdownSender {
    let (tx, mut rx) = watch::channel(false);

    tokio::spawn(async move {
        let on_revoke = Arc::new(on_revoke);

        loop {
            // Wait until it's time for the next heartbeat
            let next_hb = {
                let s = session.lock().await;
                s.next_heartbeat
            };

            let now = unix_now();
            let wait_secs = if next_hb > now { next_hb - now } else { 5 };

            tokio::select! {
                _ = sleep(Duration::from_secs(wait_secs)) => {}
                _ = rx.changed() => {
                    if *rx.borrow() { break; }
                }
            }

            // Check if session key is close to expiring (renew before TTL)
            let (expires_at, token) = {
                let s = session.lock().await;
                (s.expires_at, s.token.clone())
            };

            let now = unix_now();
            // If already expired, revoke immediately
            if now >= expires_at {
                (on_revoke)("لایسنس شما منقضی شد.".to_string());
                break;
            }

            // Send heartbeat
            let mut s = session.lock().await;
            match heartbeat(&mut s).await {
                Ok(resp) => {
                    if let Some(action) = &resp.action {
                        if action == "revoke" {
                            let msg = resp.message.unwrap_or_else(|| "لایسنس شما غیرفعال شد.".to_string());
                            drop(s);
                            (on_revoke)(msg);
                            break;
                        }
                    }
                }
                Err(LicenseError::LicenseRevoked(reason)) => {
                    let msg = format!("لایسنس شما غیرفعال شد: {}", reason);
                    drop(s);
                    (on_revoke)(msg);
                    break;
                }
                Err(LicenseError::NetworkError(_)) => {
                    // Network issue: check if we're past grace period
                    drop(s);
                    let grace_expires = {
                        let s2 = session.lock().await;
                        s2.expires_at
                    };
                    if unix_now() >= grace_expires {
                        (on_revoke)("اتصال به سرور قطع شد و مهلت سماح پایان یافت.".to_string());
                        break;
                    }
                    // Retry in 30 seconds
                    sleep(Duration::from_secs(30)).await;
                }
                Err(e) => {
                    eprintln!("[liclient] heartbeat error: {}", e);
                    // Non-fatal errors: retry next interval
                }
            }
        }
    });

    tx
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
