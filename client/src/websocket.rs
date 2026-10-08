/// WebSocket connection for instant push messages from server.
/// Receives revoke/warn commands immediately without waiting for heartbeat.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::sleep;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;

use crate::license::SERVER_URL;

/// Connect to the WebSocket endpoint and listen for push messages.
/// on_message: called with (action, message) when server pushes something
pub fn start_ws_listener(
    session_token: String,
    on_message: impl Fn(String, String) + Send + 'static,
    stop_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let on_message = Arc::new(on_message);
        let mut retry_delay = 5u64;
        let mut stop_rx = stop_rx;

        loop {
            if *stop_rx.borrow() { break; }

            let ws_url = format!(
                "{}/api/v1/ws/{}",
                SERVER_URL.replace("https://", "wss://").replace("http://", "ws://"),
                session_token
            );

            match connect_async(&ws_url).await {
                Ok((ws_stream, _)) => {
                    retry_delay = 5; // reset on success
                    let (mut write, mut read) = ws_stream.split();

                    // Ping loop (30s interval)
                    let ping_task = tokio::spawn(async move {
                        loop {
                            sleep(Duration::from_secs(30)).await;
                            let ping = serde_json::json!({"type": "ping"}).to_string();
                            if write.send(Message::Text(ping)).await.is_err() {
                                break;
                            }
                        }
                    });

                    // Read loop
                    loop {
                        tokio::select! {
                            msg = read.next() => {
                                match msg {
                                    Some(Ok(Message::Text(text))) => {
                                        if let Ok(v) = serde_json::from_str::<Value>(&text) {
                                            let action = v["action"].as_str().unwrap_or("").to_string();
                                            let message = v["message"].as_str().unwrap_or("").to_string();
                                            if !action.is_empty() {
                                                (on_message)(action, message);
                                            }
                                        }
                                    }
                                    Some(Ok(Message::Close(_))) | None => break,
                                    _ => {}
                                }
                            }
                            _ = stop_rx.changed() => {
                                if *stop_rx.borrow() { ping_task.abort(); return; }
                            }
                        }
                    }

                    ping_task.abort();
                }
                Err(e) => {
                    eprintln!("[liclient] WS connect error: {}", e);
                }
            }

            // Reconnect with backoff (max 60s)
            sleep(Duration::from_secs(retry_delay)).await;
            retry_delay = (retry_delay * 2).min(60);
        }
    });
}
