"""敏感原文保险库：原文加密保存，只凭短时凭据解密。

密文随业务事件进入哈希链日志（事件中保存的是密文，不是明文），
因此保险库状态同样可由重放重建，崩溃不丢数据。
"""
from __future__ import annotations

import os
from typing import Optional

from . import crypto


class Vault:
    def __init__(self, master_key: Optional[bytes] = None):
        self.master_key = master_key or crypto.new_master_key()
        self._sealed: dict[str, dict] = {}

    def seal(self, plaintext: str) -> tuple[str, dict]:
        blob = crypto.protect(self.master_key, plaintext.encode("utf-8"))
        secret_ref = "sec_" + os.urandom(12).hex()
        self._sealed[secret_ref] = blob
        return secret_ref, blob

    def register(self, secret_ref: str, blob: dict) -> None:
        """重放事件时重建密文索引。"""
        self._sealed[secret_ref] = blob

    def reveal(self, secret_ref: str) -> str:
        blob = self._sealed.get(secret_ref)
        if blob is None:
            raise KeyError(f"未知的敏感内容引用: {secret_ref}")
        return crypto.open_blob(self.master_key, blob).decode("utf-8")
