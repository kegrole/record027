"""汇总评估结果，生成排序、去重后的审计报告。"""
from __future__ import annotations

from typing import Any, Dict, List

from .config import CorsRule
from .rules import Evaluation, Issue, evaluate_rule


def evaluate_all(rules: List[CorsRule], requests: List[Dict[str, Any]]) -> List[Evaluation]:
    evaluations: List[Evaluation] = []
    for request in requests:
        for rule in rules:
            evaluations.append(evaluate_rule(rule, request))
    evaluations.sort(key=lambda ev: (ev.rule.rule_id, ev.request_origin))
    return evaluations


def dedup_issues(evaluations: List[Evaluation]) -> List[Issue]:
    """同一 (rule_id, request_origin, issue_type) 只保留一条，理由合并。"""
    merged: Dict[tuple, Issue] = {}
    for ev in evaluations:
        for issue in ev.issues:
            key = issue.key()
            existing = merged.get(key)
            if existing is None:
                merged[key] = Issue(issue.rule_id, issue.request_origin, issue.issue_type, issue.reason)
            elif issue.reason and issue.reason not in existing.reason:
                existing.reason = existing.reason + "；" + issue.reason
    return sorted(merged.values(), key=lambda i: (i.rule_id, i.request_origin, i.issue_type))


def build_report(rules: List[CorsRule], requests: List[Dict[str, Any]]) -> Dict[str, Any]:
    evaluations = evaluate_all(rules, requests)
    issues = dedup_issues(evaluations)
    return {
        "summary": {
            "rules": len(rules),
            "requests": len(requests),
            "evaluations": len(evaluations),
            "issues": len(issues),
            "denied": sum(1 for ev in evaluations if ev.decision == "deny"),
        },
        "evaluations": [ev.as_dict() for ev in evaluations],
        "issues": [issue.as_dict() for issue in issues],
    }

