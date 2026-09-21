"""敏感字段的保密与完整性工具。

标准库不含 AEAD 算法，这里用 HMAC-SHA256 密钥流加 Encrypt-then-MAC
实现可独立运行的封存/解封，仅用于本地开发与演示；生产部署应替换为
KMS 托管密钥的 AEAD（如 AES-GCM / ChaCha20-Poly1305），密钥不得入库。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def encrypt_text(key: bytes, plaintext: str) -> str:
    """加密文本并附带完整性校验，返回 base64 令牌。"""
    data = plaintext.encode("utf-8")
    nonce = secrets.token_bytes(16)
    cipher = bytes(a ^ b for a, b in zip(data, _keystream(key, nonce, len(data))))
    tag = hmac.new(key, b"relay-v1" + nonce + cipher, hashlib.sha256).digest()
    return base64.b64encode(nonce + tag + cipher).decode("ascii")


def decrypt_text(key: bytes, token: str) -> str:
    """解封文本；被篡改时抛出 ValueError。"""
    raw = base64.b64decode(token.encode("ascii"))
    nonce, tag, cipher = raw[:16], raw[16:48], raw[48:]
    expect = hmac.new(key, b"relay-v1" + nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("密文完整性校验失败")
    data = bytes(a ^ b for a, b in zip(cipher, _keystream(key, nonce, len(cipher))))
    return data.decode("utf-8")


def content_hash(text: str) -> str:
    """正文指纹，用于跨机构去重，不泄露原文。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def identity_lookup_key(key: bytes, child_name: str, school: str, guardian_ref: str) -> str:
    """身份查找键：HMAC 化的身份三元组，可定位保险库记录但不暴露明文。"""
    canonical = "|".join(part.strip() for part in (child_name, school, guardian_ref))
    return hmac.new(key, f"identity|{canonical}".encode("utf-8"), hashlib.sha256).hexdigest()


def new_token(prefix: str) -> str:
    """生成带前缀的随机业务标识。"""
    return f"{prefix}_{secrets.token_hex(8)}"
