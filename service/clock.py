"""时钟抽象。

业务时间（事件时间）由调用方提供，接收时间由服务端时钟产生；
时钟可注入，便于测试与故障重放。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def parse_iso(value: str) -> datetime:
    """解析 ISO 8601 时间，缺少时区时按 UTC 处理。"""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_iso(dt: datetime) -> str:
    """统一为 UTC 的 ISO 8601 字符串。"""
    return dt.astimezone(timezone.utc).isoformat()


class SystemClock:
    """生产时钟。"""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class ManualClock:
    """测试用可推进时钟。"""

    def __init__(self, start: datetime):
        self._now = start.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs) -> None:
        self._now = self._now + timedelta(**kwargs)
