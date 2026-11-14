"""Origin 解析与匹配。

所有匹配都基于 (scheme, host, port) 三元组与通配分量对齐实现，
不做任何字符串前后缀比较。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit

DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}


class PatternKind(Enum):
    EXACT = "exact"
    WILDCARD = "wildcard"
    STAR = "star"
    NULL = "null"
    REGEX = "regex"


@dataclass(frozen=True)
class OriginPattern:
    kind: PatternKind
    raw: str
    body: str = ""
    regex_form: str = ""  # "prefix" 或 "wrapped"，仅正则形态使用


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: Optional[int]

    @property
    def effective_port(self) -> Optional[int]:
        if self.port is not None:
            return self.port
        return DEFAULT_PORTS.get(self.scheme)


def parse_origin(raw: object) -> Optional[Origin]:
    """把 origin 字符串解析为规范化三元组；无法解析时返回 None。

    scheme 与 host 统一小写；端口保留显式值，缺省时由 effective_port
    按 scheme 补默认端口。
    """
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or text == "null":
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    host = parts.hostname
    if not scheme or not host:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    return Origin(scheme=scheme, host=host.lower(), port=port)


def classify_pattern(pattern: str) -> OriginPattern:
    """识别规则写法：精确、子域通配、任意星号、null、正则（前缀 / 包裹）。"""
    text = str(pattern).strip()
    if text == "*":
        return OriginPattern(PatternKind.STAR, text)
    if text == "null":
        return OriginPattern(PatternKind.NULL, text)
    if len(text) > 2 and text.startswith("/") and text.endswith("/"):
        return OriginPattern(PatternKind.REGEX, text, body=text[1:-1], regex_form="wrapped")
    if text.startswith("^"):
        return OriginPattern(PatternKind.REGEX, text, body=text, regex_form="prefix")
    if text.startswith("(?"):
        return OriginPattern(PatternKind.REGEX, text, body=text, regex_form="prefix")
    if "*" in text:
        return OriginPattern(PatternKind.WILDCARD, text)
    return OriginPattern(PatternKind.EXACT, text)


def _match_exact(pattern_body: str, origin: Origin) -> bool:
    expected = parse_origin(pattern_body)
    if expected is None:
        return False
    return (
        expected.scheme == origin.scheme
        and expected.host == origin.host
        and expected.effective_port == origin.effective_port
    )


def _match_wildcard(pattern_body: str, origin: Origin) -> bool:
    """子域通配：* 只占一个分量，按分量逐一比对，分量数必须相等。"""
    text = pattern_body
    if "://" in text:
        pattern_scheme, _, text = text.partition("://")
        if pattern_scheme.lower() != origin.scheme:
            return False
    host_part = text
    if ":" in text:
        candidate_host, _, candidate_port = text.rpartition(":")
        if candidate_port.isdigit():
            host_part = candidate_host
            if int(candidate_port) != origin.effective_port:
                return False
    pattern_labels = host_part.lower().split(".")
    origin_labels = origin.host.split(".")
    if len(pattern_labels) != len(origin_labels):
        return False
    return all(p == "*" or p == o for p, o in zip(pattern_labels, origin_labels))


def _match_regex(pattern: OriginPattern, request_origin_raw: str) -> bool:
    """正则匹配作用于请求 origin 的原始字符串，默认大小写敏感。

    规则作者可自行在正则里加 (?i) 获得大小写不敏感语义。
    """
    try:
        if pattern.regex_form == "wrapped":
            return re.fullmatch(pattern.body, request_origin_raw) is not None
        return re.match(pattern.body, request_origin_raw) is not None
    except re.error:
        return False


def origin_matches(pattern_raw: str, request_origin_raw: str) -> bool:
    """判断单条 origin 规则是否命中请求 origin（不含 null 三态裁决）。"""
    pattern = classify_pattern(pattern_raw)
    request_text = str(request_origin_raw).strip()
    if pattern.kind is PatternKind.STAR:
        return request_text != "null"
    if pattern.kind is PatternKind.NULL:
        return request_text == "null"
    if pattern.kind is PatternKind.REGEX:
        return _match_regex(pattern, request_text)
    origin = parse_origin(request_text)
    if origin is None:
        return False
    if pattern.kind is PatternKind.EXACT:
        return _match_exact(pattern.raw, origin)
    if pattern.kind is PatternKind.WILDCARD:
        return _match_wildcard(pattern.raw, origin)
    return False
