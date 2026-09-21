"""内置加密原语（演示/教学级）。

仅依赖 Python 标准库：HKDF 风格的 HMAC-SHA256 密钥派生、
HMAC 伪随机流加密与 Encrypt-then-MAC 完整性保护。

注意：这不是经过专业审计的 AEAD。生产部署必须替换为 AES-GCM /
XChaCha20-Poly1305 等经审计算法，并由 KMS/HSM 托管主密钥。
本模块的目标是让“原文不落明文、读取需凭据”的领域约束可运行、可测试。
"""
from __future__ import annotations

import hashlib
import hmac
import os


def new_master_key() -> bytes:
    return os.urandom(32)


def _prf(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _derive(master: bytes, salt: bytes, info: bytes) -> bytes:
    # HKDF-Extract / Expand 的简化形态
    prk = _prf(master, salt)
    return _prf(prk, info)


def _keystream(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += _prf(seed, b"stream" + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def protect(master: bytes, plaintext: bytes) -> dict:
    nonce = os.urandom(16)
    enc_seed = _derive(master, nonce, b"letter-relay/v1/enc")
    mac_seed = _derive(master, nonce, b"letter-relay/v1/mac")
    stream = _keystream(enc_seed, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(stream, plaintext))
    tag = hmac.new(mac_seed, nonce + ciphertext, hashlib.sha256).digest()
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }


def open_blob(master: bytes, sealed: dict) -> bytes:
    nonce = bytes.fromhex(sealed["nonce"])
    ciphertext = bytes.fromhex(sealed["ciphertext"])
    tag = bytes.fromhex(sealed["tag"])
    mac_seed = _derive(master, nonce, b"letter-relay/v1/mac")
    expected = hmac.new(mac_seed, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("密文完整性校验失败")
    enc_seed = _derive(master, nonce, b"letter-relay/v1/enc")
    stream = _keystream(enc_seed, len(ciphertext))
    return bytes(a ^ b for a, b in zip(stream, ciphertext))
