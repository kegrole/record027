"""CORS 规则配置解析：从 JSON 载入规则与请求。"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CorsRule:
    """一条 CORS 策略规则。"""

    rule_id: str
    allowed_origins: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=list)
    allowed_headers: List[str] = field(default_factory=list)
    exposed_headers: List[str] = field(default_factory=list)
    allow_credentials: bool = False
    max_age: Any = None  # 保留原始值，边界校验在 preflight 模块完成

    def allows_method(self, method: str) -> bool:
        return method.lower() in {m.lower() for m in self.allowed_methods}

    def allowed_header_names(self) -> set:
        return {h.lower() for h in self.allowed_headers}


def rule_from_dict(data: Dict[str, Any], index: int = 0) -> CorsRule:
    if not isinstance(data, dict):
        raise ValueError(f"rule #{index} must be a JSON object")
    rule_id = data.get("rule_id") or f"rule-{index}"
    return CorsRule(
        rule_id=str(rule_id),
        allowed_origins=[str(o) for o in data.get("allowed_origins", [])],
        allowed_methods=[str(m) for m in data.get("allowed_methods", [])],
        allowed_headers=[str(h) for h in data.get("allowed_headers", [])],
        exposed_headers=[str(h) for h in data.get("exposed_headers", [])],
        allow_credentials=bool(data.get("allow_credentials", False)),
        max_age=data.get("max_age"),
    )


def _load_items(path: str, key: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, dict):
        payload = payload.get(key, [])
    if not isinstance(payload, list):
        raise ValueError(f"{path} must contain a JSON list")
    return payload


def load_rules(path: str) -> List[CorsRule]:
    return [rule_from_dict(item, i) for i, item in enumerate(_load_items(path, "rules"))]


def load_requests(path: str) -> List[Dict[str, Any]]:
    return [item for item in _load_items(path, "requests")]

