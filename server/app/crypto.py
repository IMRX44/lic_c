"""
Cryptographic utilities for the licensing system.

- Ed25519: signing session tokens (private key stays on server)
- AES-256-GCM: encrypting session keys sent to client
- HMAC-SHA256: request integrity verification
- Argon2id: admin password hashing
"""
import os
import hmac
import hashlib
import secrets
import struct
import time
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

_private_key: Optional[Ed25519PrivateKey] = None
_public_key_hex: Optional[str] = None


def load_or_generate_keys(private_path: str, public_path: str) -> str:
    """Load existing Ed25519 key pair or generate a new one. Returns public key hex."""
    global _private_key, _public_key_hex

    os.makedirs(os.path.dirname(private_path), exist_ok=True)

    if os.path.exists(private_path):
        with open(private_path, "rb") as f:
            _private_key = load_pem_private_key(f.read(), password=None)
    else:
        _private_key = Ed25519PrivateKey.generate()
        with open(private_path, "wb") as f:
            f.write(_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        pub = _private_key.public_key()
        with open(public_path, "wb") as f:
            f.write(pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))

    pub_bytes = _private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _public_key_hex = pub_bytes.hex()
    return _public_key_hex


def sign_payload(payload: bytes) -> bytes:
    """Sign arbitrary bytes with server Ed25519 private key."""
    if _private_key is None:
        raise RuntimeError("Keys not loaded")
    return _private_key.sign(payload)


def get_public_key_hex() -> str:
    if _public_key_hex is None:
        raise RuntimeError("Keys not loaded")
    return _public_key_hex


def generate_session_key() -> bytes:
    """Generate a 32-byte AES-256 session key."""
    return secrets.token_bytes(32)


def encrypt_session_key(session_key: bytes, hwid_hash: str, license_id: str) -> str:
    """
    Encrypt session_key using a key derived from HWID and license_id.
    The client derives the same key from its HWID and license_id to decrypt.
    Returns hex-encoded ciphertext (nonce + ciphertext + tag).
    """
    # Derive wrapping key: HKDF-like derivation from HWID + license_id
    material = f"{hwid_hash}:{license_id}".encode()
    wrapping_key = hashlib.sha256(material).digest()

    aesgcm = AESGCM(wrapping_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, session_key, None)
    return (nonce + ciphertext).hex()


def build_session_token(
    license_id: str,
    hwid_hash: str,
    product_slug: str,
    expires_at: int,
    sequence: int,
) -> str:
    """
    Build a signed session token.
    Format (binary): license_id(36) | hwid_hash(64) | product_slug(32) | expires_at(8) | seq(4)
    Returns: hex(payload) + "." + hex(signature)
    """
    # Pad/truncate fields to fixed sizes
    payload = (
        license_id.encode().ljust(36)[:36] +
        hwid_hash.encode().ljust(64)[:64] +
        product_slug.encode().ljust(32)[:32] +
        struct.pack(">Q", expires_at) +
        struct.pack(">I", sequence)
    )
    sig = sign_payload(payload)
    return payload.hex() + "." + sig.hex()


def verify_session_token(token: str) -> Optional[dict]:
    """
    Verify and decode a session token.
    Returns dict with fields or None if invalid.
    """
    try:
        payload_hex, sig_hex = token.split(".")
        payload = bytes.fromhex(payload_hex)
        sig = bytes.fromhex(sig_hex)

        pub_raw = bytes.fromhex(get_public_key_hex())
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        pub.verify(sig, payload)  # raises if invalid

        license_id = payload[0:36].decode().strip()
        hwid_hash = payload[36:100].decode().strip()
        product_slug = payload[100:132].decode().strip()
        expires_at = struct.unpack(">Q", payload[132:140])[0]
        sequence = struct.unpack(">I", payload[140:144])[0]

        if int(time.time()) > expires_at:
            return None

        return {
            "license_id": license_id,
            "hwid_hash": hwid_hash,
            "product_slug": product_slug,
            "expires_at": expires_at,
            "sequence": sequence,
        }
    except Exception:
        return None


def verify_request_hmac(body: bytes, received_hmac: str, secret: str) -> bool:
    """Verify HMAC-SHA256 of request body."""
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, received_hmac)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, hash_: str) -> bool:
    try:
        return ph.verify(hash_, password)
    except VerifyMismatchError:
        return False


def generate_license_key() -> str:
    """Generate a formatted license key: XXXX-XXXX-XXXX-XXXX-XXXX"""
    raw = secrets.token_hex(10).upper()
    parts = [raw[i:i+4] for i in range(0, 20, 4)]
    return "-".join(parts)
