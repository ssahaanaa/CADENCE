"""CADENCE legacy encrypted-file migration.

Converts supported legacy symmetric ciphertext into an authenticated
AES-256-GCM container. This intentionally requires the old algorithm and
old key: arbitrary ciphertext cannot be safely migrated without them.
"""
from __future__ import annotations

import os
from pathlib import Path

from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish
from Crypto.Util.Padding import unpad

MAGIC = b"CADENCE-AES256-GCM-V1\n"


def _key_bytes(value: str, *, label: str) -> bytes:
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{label} is required")
    if value.startswith("hex:"):
        raw = value[4:].strip()
        try:
            return bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError(f"{label} has invalid hex") from exc
    return value.encode("utf-8")


def _iv_bytes(value: str, size: int) -> bytes:
    if not value:
        return b"\x00" * size
    raw = _key_bytes(value, label="IV")
    if len(raw) != size:
        raise ValueError(f"IV must be exactly {size} bytes")
    return raw


def decrypt_legacy(data: bytes, algorithm: str, key_value: str, mode: str = "ECB", iv_value: str = "") -> bytes:
    algorithm = algorithm.upper().replace("-", "")
    mode = mode.upper()
    key = _key_bytes(key_value, label="Old key")

    if algorithm == "DES":
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes")
        if mode == "ECB":
            cipher = DES.new(key, DES.MODE_ECB)
        elif mode == "CBC":
            cipher = DES.new(key, DES.MODE_CBC, _iv_bytes(iv_value, 8))
        else:
            raise ValueError("DES supports ECB or CBC in this migration tool")
        return unpad(cipher.decrypt(data), 8)

    if algorithm in {"3DES", "TRIPLEDES", "DES3"}:
        if len(key) not in (16, 24):
            raise ValueError("3DES key must be 16 or 24 bytes")
        if not DES3.key_check(key):
            raise ValueError("3DES key is not valid")
        if mode == "ECB":
            cipher = DES3.new(key, DES3.MODE_ECB)
        elif mode == "CBC":
            cipher = DES3.new(key, DES3.MODE_CBC, _iv_bytes(iv_value, 8))
        else:
            raise ValueError("3DES supports ECB or CBC in this migration tool")
        return unpad(cipher.decrypt(data), 8)

    if algorithm == "BLOWFISH":
        if not 4 <= len(key) <= 56:
            raise ValueError("Blowfish key must be 4 to 56 bytes")
        if mode == "ECB":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        elif mode == "CBC":
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, _iv_bytes(iv_value, 8))
        else:
            raise ValueError("Blowfish supports ECB or CBC in this migration tool")
        return unpad(cipher.decrypt(data), 8)

    if algorithm == "RC4":
        if not 5 <= len(key) <= 256:
            raise ValueError("RC4 key must be 5 to 256 bytes")
        return ARC4.new(key).decrypt(data)

    raise ValueError("Unsupported legacy algorithm. Choose DES, 3DES, RC4, or Blowfish.")


def encrypt_aes_gcm(plaintext: bytes, new_key_value: str = "") -> tuple[bytes, bytes]:
    if new_key_value.strip():
        key = _key_bytes(new_key_value, label="New AES key")
        if len(key) != 32:
            raise ValueError("New AES-256 key must be exactly 32 bytes")
    else:
        key = os.urandom(32)

    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # Self-describing binary container: magic | nonce | tag | ciphertext.
    return MAGIC + nonce + tag + ciphertext, key


def migrate_bytes(data: bytes, algorithm: str, old_key: str, mode: str = "ECB", iv: str = "", new_key: str = "") -> tuple[bytes, bytes]:
    plaintext = decrypt_legacy(data, algorithm, old_key, mode, iv)
    return encrypt_aes_gcm(plaintext, new_key)
