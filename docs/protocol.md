# پروتکل فعال‌سازی و Heartbeat

## جریان فعال‌سازی

```
Client                                    Server
  |                                          |
  |-- POST /api/v1/activate ---------------->|
  |   {license_key, hwid_hash, product_slug, |
  |    platform, nonce, timestamp}           |
  |                                          |
  |<-- {session_token, session_key_hex, ------|
  |     expires_at, heartbeat_interval}      |
  |                                          |
  |-- WS /api/v1/ws/{session_token} -------->|
  |   (keep-alive WebSocket connection)      |
  |                                          |
  [هر heartbeat_interval ثانیه:]            |
  |-- POST /api/v1/heartbeat --------------->|
  |   {session_token, hwid_hash, nonce,      |
  |    timestamp}                            |
  |                                          |
  |<-- {session_key_hex, expires_at, --------|
  |     next_heartbeat}                      |
```

## جریان لغو/تعلیق فوری

```
Admin Panel                 Server                  Client
    |                          |                        |
    |-- POST /revoke ---------->|                        |
    |                          |-- WS push: revoke ----->|
    |                          |   {countdown: 10s}     |
    |                          |                        |
    |                          |   [client shows         |
    |                          |    countdown dialog]    |
    |                          |                        |
    |                          |   [after 10s: exit]    |
    |                          |                        |
    |                          |-- heartbeat fails ----->|
    |                          |   403 license_revoked  |
```

## امنیت

### HWID Hash
- `HWID_Hash = SHA-256(raw_hwid + ":" + license_key[:8])`
- raw_hwid هرگز به سرور ارسال نمی‌شود
- سرور فقط hash می‌بیند

### Session Key
- سرور کلید AES-256 تولید می‌کند
- آن را با `SHA-256(hwid_hash + ":" + license_id)` رمز می‌کند
- کلاینت از HWID و license_id خودش همان کلید را مشتق می‌کند و رمزگشایی می‌کند
- کلید رمزگشایی هرگز در شبکه نمی‌رود

### Token Signing (Ed25519)
- سرور با کلید خصوصی Ed25519 امضا می‌کند
- کلید عمومی در باینری کلاینت burn می‌شود (compile-time pinning)
- کلاینت هر token را قبل از استفاده verify می‌کند

### Replay Protection
- هر درخواست یک UUID nonce دارد
- سرور در Redis (TTL=120s) نگه می‌دارد
- نانس تکراری = رد شدن درخواست

### Sequence Counter
- هر token شماره‌ی صعودی دارد
- برگرداندن ساعت سیستم را ناکارآمد می‌کند

## بارگذاری تخمینی

| کاربران همزمان | heartbeat (هر 60s) | req/s |
|---|---|---|
| 100 | — | ~1.7 |
| 500 | — | ~8.3 |
| 1000 | — | ~16.7 |
| 1000 | + WS ping (30s) | ~33 |

یک VPS با 2 core و 4GB RAM با این بار به راحتی کنار می‌آید.
