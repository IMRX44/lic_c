# LicenseSystem

سیستم لایسنس آنلاین با پنل مدیریت، برای ویندوز و لینوکس.

## ساختار

```
lic_c/
├── server/             ← سرور FastAPI + پنل ادمین
│   ├── app/
│   │   ├── main.py
│   │   ├── models.py       ← جداول DB (Product, License, Activation, AuditLog)
│   │   ├── licensing.py    ← منطق activate و heartbeat
│   │   ├── crypto.py       ← Ed25519, AES-256-GCM, Argon2id
│   │   ├── auth.py         ← احراز هویت ادمین + TOTP
│   │   ├── redis_client.py ← سشن، نانس، سیت
│   │   ├── websocket_manager.py ← push فوری
│   │   └── routers/
│   │       ├── license_api.py   ← /api/v1/* (کلاینت)
│   │       └── admin.py         ← /admin/api/* (پنل)
│   ├── panel/templates/    ← HTML پنل ادمین
│   ├── docker-compose.yml
│   ├── nginx.conf
│   └── requirements.txt
├── client/             ← SDK کلاینت Rust
│   ├── src/
│   │   ├── lib.rs          ← LicenseGuard (رابط اصلی)
│   │   ├── hwid.rs         ← شناسه سخت‌افزاری
│   │   ├── license.rs      ← activate + heartbeat
│   │   ├── crypto.rs       ← verify token + decrypt session key
│   │   ├── heartbeat.rs    ← loop پس‌زمینه
│   │   ├── websocket.rs    ← دریافت push فوری
│   │   └── error.rs
│   └── build.rs            ← bake server URL + public key into binary
└── docs/
    └── protocol.md
```

## راه‌اندازی سرور

```bash
cd server
cp .env.example .env
# ویرایش .env
docker-compose up -d
```

بعد از راه‌اندازی:
- پنل ادمین: `https://yourdomain.com/panel`
- سلامت: `https://yourdomain.com/health`

## دریافت کلید عمومی Ed25519

بعد از راه‌اندازی سرور، کلید عمومی در لاگ چاپ می‌شود. یا:

```bash
docker exec <container> python3 -c "
from app.crypto import load_or_generate_keys, get_public_key_hex
load_or_generate_keys('./keys/ed25519_private.pem', './keys/ed25519_public.pem')
print(get_public_key_hex())
"
```

## build کلاینت

```bash
cd client
export LICENSE_SERVER_URL="https://yourdomain.com"
export SERVER_PUBLIC_KEY_HEX="<کلید عمومی از مرحله بالا>"

# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# Windows (cross-compile از Linux)
cargo build --release --target x86_64-pc-windows-gnu
```

## استفاده در برنامه

```rust
use liclient::{LicenseGuard, LicenseConfig};

#[tokio::main]
async fn main() {
    let _guard = LicenseGuard::new(LicenseConfig {
        license_key: std::env::var("LICENSE_KEY").unwrap(),
        product_slug: "your-product".to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
    })
    .on_revoke(|msg| {
        eprintln!("{}", msg);
        std::thread::sleep(std::time::Duration::from_secs(10));
        std::process::exit(1);
    })
    .activate()
    .await
    .expect("فعال‌سازی ناموفق");

    // برنامه شما اینجا
    your_app_main().await;
}
```

## امنیت

- **server URL و کلید عمومی** در زمان compile درون باینری قرار می‌گیرند
- **HWID** فقط به‌صورت hash ارسال می‌شود
- **Session key** با کلید مشتق‌شده از HWID رمز می‌شود
- **WebSocket** برای قطع فوری (۱۰ ثانیه شمارش معکوس)
- **TOTP اجباری** برای ادمین
