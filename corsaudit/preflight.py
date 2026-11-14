"""预检响应与缓存秒数检查。"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

MAX_AGE_LIMIT = 86400

IssueSpec = Tuple[str, str]  # (issue_type, reason)


def response_headers(response: Dict[str, Any]) -> Dict[str, str]:
    raw = (response or {}).get("headers") or {}
    return {str(k).lower(): str(v) for k, v in raw.items()}


def response_has_vary_origin(response: Dict[str, Any]) -> bool:
    vary = response_headers(response).get("vary", "")
    return any(token.strip().lower() == "origin" for token in vary.split(","))


def check_max_age(raw: Any, source: str) -> List[IssueSpec]:
    """Access-Control-Max-Age 边界：超上限 / 负数 / 无法解析；缺省不报。"""
    if raw is None:
        return []
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return [("max_age_invalid", f"{source}的 Access-Control-Max-Age 值 {raw!r} 无法解析为数字")]
    if value < 0:
        return [("max_age_negative", f"{source}的 Access-Control-Max-Age 为负数 {value}")]
    if value > MAX_AGE_LIMIT:
        return [("max_age_too_large", f"{source}的 Access-Control-Max-Age {value} 超过上限 {MAX_AGE_LIMIT}")]
    return []


def check_config_max_age(raw: Any) -> List[IssueSpec]:
    return check_max_age(raw, "规则配置")


def check_preflight_response(rule: Any, response: Dict[str, Any]) -> List[IssueSpec]:
    """凭证为真时检查预检响应的回显 origin 与 Vary: Origin 组合。"""
    issues: List[IssueSpec] = []
    headers = response_headers(response)
    if rule.allow_credentials:
        echoed = headers.get("access-control-allow-origin", "").strip()
        if echoed == "*":
            issues.append((
                "echo_wildcard_with_credentials",
                "允许凭证的规则的预检响应把 Access-Control-Allow-Origin 回显为 *，浏览器会拒绝且配置自相矛盾",
            ))
        if not response_has_vary_origin(response):
            issues.append((
                "missing_vary",
                "允许凭证的规则的预检响应缺少 Vary: Origin，共享缓存可能把响应错发给其他 origin",
            ))
    if "access-control-max-age" in headers:
        issues.extend(check_max_age(headers["access-control-max-age"], "预检响应"))
    return issues

