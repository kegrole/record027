"""单条 CORS 规则对单个请求的判定。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .config import CorsRule
from .origin import PatternKind, classify_pattern, origin_matches
from .preflight import (
    check_config_max_age,
    check_preflight_response,
    response_has_vary_origin,
)


@dataclass
class Issue:
    rule_id: str
    request_origin: str
    issue_type: str
    reason: str

    def key(self):
        return (self.rule_id, self.request_origin, self.issue_type)

    def as_dict(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "request_origin": self.request_origin,
            "issue_type": self.issue_type,
            "reason": self.reason,
        }


@dataclass
class Evaluation:
    rule: CorsRule
    request_origin: str
    decision: str
    reason: str
    issues: List[Issue] = field(default_factory=list)

    def issue_types(self) -> List[str]:
        return sorted({issue.issue_type for issue in self.issues})

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "request_origin": self.request_origin,
            "allowed_methods": list(self.rule.allowed_methods),
            "credentials": self.rule.allow_credentials,
            "decision": self.decision,
            "reason": self.reason,
            "issues": self.issue_types(),
        }


def evaluate_rule(rule: CorsRule, request: Dict[str, Any]) -> Evaluation:
    request_origin = str(request.get("origin", "")).strip()
    issues: List[Issue] = []
    notes: List[str] = []

    def add(issue_type: str, reason: str) -> None:
        issues.append(Issue(rule.rule_id, request_origin, issue_type, reason))

    kinds = [classify_pattern(p).kind for p in rule.allowed_origins]
    has_star = PatternKind.STAR in kinds
    has_null = PatternKind.NULL in kinds

    if has_star and rule.allow_credentials:
        add(
            "wildcard_with_credentials",
            "规则 origin 为 * 且允许凭证：任意站点都能发起带凭证的跨域请求，属于危险配置",
        )

    if request_origin == "null":
        if rule.allow_credentials:
            add(
                "null_with_credentials",
                "请求 origin 为 null 且规则允许凭证：null origin 来源不可信，一律拒绝",
            )
        elif has_null:
            notes.append("null_origin_allowed")
        elif has_star:
            add(
                "null_with_wildcard",
                "请求 origin 为 null 而规则为 *：不允许用星号放行 null origin",
            )
        else:
            add(
                "null_with_exact",
                "请求 origin 为 null 而规则为精确匹配：null 不等于任何具体 origin",
            )
    else:
        if not any(origin_matches(p, request_origin) for p in rule.allowed_origins):
            add(
                "origin_not_allowed",
                f"请求 origin {request_origin} 未命中规则 {rule.rule_id} 的任何允许项",
            )
        if has_star:
            request_header_names = {str(k).lower() for k in (request.get("headers") or {})}
            if "cookie" in request_header_names:
                add(
                    "wildcard_with_cookie_request",
                    "规则 origin 为 * 且请求携带 Cookie 头： Cookie 会随响应暴露给任意站点",
                )
            response = request.get("response")
            if response is not None and not response_has_vary_origin(response):
                add(
                    "wildcard_without_vary",
                    "规则 origin 为 * 且响应缺少 Vary: Origin：共享缓存可能把响应错发给其他 origin",
                )

    method = request.get("method")
    if method is not None and not rule.allows_method(str(method)):
        add(
            "method_not_allowed",
            f"请求方法 {method} 不在规则 {rule.rule_id} 的允许列表 {rule.allowed_methods} 中",
        )

    allowed_headers = rule.allowed_header_names()
    bad_headers = [
        str(h) for h in (request.get("request_headers") or [])
        if str(h).lower() not in allowed_headers
    ]
    if bad_headers:
        add(
            "header_not_allowed",
            f"请求头 {', '.join(bad_headers)} 不在规则 {rule.rule_id} 的允许列表中",
        )

    response = request.get("response")
    if response is not None:
        for issue_type, reason in check_preflight_response(rule, response):
            add(issue_type, reason)
    for issue_type, reason in check_config_max_age(rule.max_age):
        add(issue_type, reason)

    decision = "deny" if issues else "allow"
    if issues:
        reason = ";".join(sorted({issue.issue_type for issue in issues}))
    elif notes:
        reason = ";".join(notes)
    else:
        reason = ""
    return Evaluation(
        rule=rule,
        request_origin=request_origin,
        decision=decision,
        reason=reason,
        issues=issues,
    )

