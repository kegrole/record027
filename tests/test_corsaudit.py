"""corsaudit 判定口径测试：每条口径至少一个正例一个反例。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from corsaudit.config import load_rules, rule_from_dict
from corsaudit.origin import PatternKind, classify_pattern, origin_matches
from corsaudit.rules import evaluate_rule
from corsaudit.report import build_report


def make_rule(rule_id="r1", origins=None, methods=None, headers=None,
              credentials=False, max_age=None, exposed=None):
    return rule_from_dict({
        "rule_id": rule_id,
        "allowed_origins": origins if origins is not None else ["https://app.example.com"],
        "allowed_methods": methods if methods is not None else ["GET", "POST"],
        "allowed_headers": headers if headers is not None else ["Content-Type"],
        "exposed_headers": exposed or [],
        "allow_credentials": credentials,
        "max_age": max_age,
    })


def make_request(origin="https://app.example.com", method="GET",
                 request_headers=None, headers=None, response=None):
    request = {"origin": origin, "method": method}
    if request_headers is not None:
        request["request_headers"] = request_headers
    if headers is not None:
        request["headers"] = headers
    if response is not None:
        request["response"] = response
    return request


def issue_types(evaluation):
    return {issue.issue_type for issue in evaluation.issues}


def build_nine_rules():
    """口径 1 的 9 条 origin 规则：3 精确、2 子域通配、1 星号、1 null、1 带端口、1 正则。"""
    return [
        make_rule("exact-app", ["https://app.example.com"]),
        make_rule("exact-http-scheme", ["http://app.example.com"]),
        make_rule("exact-parent", ["https://example.com"]),
        make_rule("wildcard-sub", ["*.example.com"]),
        make_rule("wildcard-deep", ["*.*.example.com"]),
        make_rule("star", ["*"]),
        make_rule("null", ["null"]),
        make_rule("exact-alt-port", ["https://app.example.com:8443"]),
        make_rule("regex-app", ["^https://app\\.example\\.com$"]),
    ]


class Test01RuleFixtures(unittest.TestCase):
    """口径 1：9 条规则的形态识别。"""

    def test_nine_rules_classified(self):
        rules = build_nine_rules()
        self.assertEqual(len(rules), 9)
        kinds = [classify_pattern(r.allowed_origins[0]).kind for r in rules]
        self.assertEqual(kinds.count(PatternKind.EXACT), 4)  # 3 精确 + 1 带端口
        self.assertEqual(kinds.count(PatternKind.WILDCARD), 2)
        self.assertEqual(kinds.count(PatternKind.STAR), 1)
        self.assertEqual(kinds.count(PatternKind.NULL), 1)
        self.assertEqual(kinds.count(PatternKind.REGEX), 1)

    def test_classification_negative(self):
        self.assertIsNot(classify_pattern("*.example.com").kind, PatternKind.EXACT)
        self.assertIsNot(classify_pattern("https://app.example.com").kind, PatternKind.WILDCARD)
        self.assertIsNot(classify_pattern("null").kind, PatternKind.STAR)


class Test02FixedOriginMatching(unittest.TestCase):
    """口径 2：固定请求 https://app.example.com 的命中与拒绝。"""

    ORIGIN = "https://app.example.com"

    def test_hits(self):
        self.assertTrue(origin_matches("https://app.example.com", self.ORIGIN))
        self.assertTrue(origin_matches("*.example.com", self.ORIGIN))

    def test_misses(self):
        self.assertFalse(origin_matches("http://app.example.com", self.ORIGIN))  # scheme 不同
        self.assertFalse(origin_matches("https://app.example.com:8443", self.ORIGIN))  # 端口不同
        self.assertFalse(origin_matches("https://example.com", self.ORIGIN))  # 父域不同


class Test03WildcardComponentAlignment(unittest.TestCase):
    """口径 3：通配按分量对齐，不做后缀比较。"""

    def test_positive(self):
        self.assertTrue(origin_matches("*.*.example.com", "https://a.b.example.com"))
        self.assertTrue(origin_matches("*.example.com", "https://app.example.com"))

    def test_negative(self):
        self.assertFalse(origin_matches("*.example.com", "https://evil.example.com.attacker.net"))
        self.assertFalse(origin_matches("*.example.com", "https://a.b.example.com"))
        self.assertFalse(origin_matches("*.example.com", "https://example.com"))
        self.assertFalse(origin_matches("*.*.example.com", "https://a.example.com"))


class Test04DefaultPortEquivalence(unittest.TestCase):
    """口径 4：默认端口与显式端口等价，scheme 必须一致。"""

    def test_default_port_matches_explicit(self):
        self.assertTrue(origin_matches("https://app.example.com", "https://app.example.com:443"))
        self.assertTrue(origin_matches("https://app.example.com:443", "https://app.example.com"))

    def test_same_port_different_scheme_rejected(self):
        self.assertFalse(origin_matches("https://app.example.com:443", "http://app.example.com:443"))
        self.assertFalse(origin_matches("http://app.example.com", "https://app.example.com"))


class Test05NullOriginThreeStates(unittest.TestCase):
    """口径 5：null origin 三态 + 凭证一律拒绝。"""

    def test_null_rule_without_credentials_allowed(self):
        ev = evaluate_rule(make_rule(origins=["null"], credentials=False), make_request(origin="null"))
        self.assertEqual(ev.decision, "allow")
        self.assertEqual(ev.reason, "null_origin_allowed")

    def test_null_with_wildcard_rejected(self):
        ev = evaluate_rule(make_rule(origins=["*"], credentials=False), make_request(origin="null"))
        self.assertEqual(ev.decision, "deny")
        self.assertIn("null_with_wildcard", issue_types(ev))

    def test_null_with_exact_rejected(self):
        ev = evaluate_rule(make_rule(origins=["https://app.example.com"], credentials=False),
                           make_request(origin="null"))
        self.assertEqual(ev.decision, "deny")
        self.assertIn("null_with_exact", issue_types(ev))

    def test_null_with_credentials_always_rejected(self):
        for origins in (["null"], ["*"], ["https://app.example.com"]):
            ev = evaluate_rule(make_rule(origins=origins, credentials=True), make_request(origin="null"))
            self.assertEqual(ev.decision, "deny", origins)
            self.assertNotEqual(ev.reason, "null_origin_allowed", origins)


class Test06CaseSensitivityAndRegex(unittest.TestCase):
    """口径 6：大写请求 origin 对精确/通配规则匹配，对正则默认不匹配。"""

    UPPER = "HTTPS://APP.EXAMPLE.COM"

    def test_uppercase_matches_exact_and_wildcard(self):
        self.assertTrue(origin_matches("https://app.example.com", self.UPPER))
        self.assertTrue(origin_matches("*.example.com", self.UPPER))

    def test_uppercase_regex_default_no_match(self):
        self.assertFalse(origin_matches("^https://app\\.example\\.com$", self.UPPER))
        self.assertFalse(origin_matches("/^https:\\/\\/app\\.example\\.com$/", self.UPPER))

    def test_regex_with_ignore_case_flag_matches(self):
        self.assertTrue(origin_matches("(?i)^https://app\\.example\\.com$", self.UPPER))

    def test_regex_positive_lowercase(self):
        self.assertTrue(origin_matches("^https://app\\.example\\.com$", "https://app.example.com"))
        self.assertTrue(origin_matches("/^https:\\/\\/app\\.example\\.com$/", "https://app.example.com"))


class Test07WildcardCredentialsIssues(unittest.TestCase):
    """口径 7：星号与凭证互斥的三种情形分别报告。"""

    def test_wildcard_with_credentials(self):
        ev = evaluate_rule(make_rule(origins=["*"], credentials=True), make_request())
        self.assertIn("wildcard_with_credentials", issue_types(ev))

    def test_wildcard_with_cookie_request(self):
        ev = evaluate_rule(make_rule(origins=["*"], credentials=False),
                           make_request(headers={"Cookie": "session=abc"}))
        self.assertIn("wildcard_with_cookie_request", issue_types(ev))

    def test_wildcard_without_vary(self):
        response = {"headers": {"Access-Control-Allow-Origin": "*"}}
        ev = evaluate_rule(make_rule(origins=["*"], credentials=False),
                           make_request(response=response))
        self.assertIn("wildcard_without_vary", issue_types(ev))

    def test_no_star_no_issue(self):
        ev = evaluate_rule(make_rule(origins=["https://app.example.com"], credentials=True),
                           make_request(headers={"Cookie": "session=abc"}))
        self.assertNotIn("wildcard_with_credentials", issue_types(ev))
        self.assertNotIn("wildcard_with_cookie_request", issue_types(ev))


class Test08PreflightAndMaxAge(unittest.TestCase):
    """口径 8：预检回显与 Vary 四组合 + 缓存秒数三种边界。"""

    def evaluate(self, acao=None, vary=None, max_age=None, credentials=True):
        headers = {}
        if acao is not None:
            headers["Access-Control-Allow-Origin"] = acao
        if vary is not None:
            headers["Vary"] = vary
        if max_age is not None:
            headers["Access-Control-Max-Age"] = max_age
        rule = make_rule(credentials=credentials)
        return evaluate_rule(rule, make_request(response={"headers": headers}))

    def test_exact_echo_with_vary_passes(self):
        ev = self.evaluate(acao="https://app.example.com", vary="Origin")
        self.assertNotIn("echo_wildcard_with_credentials", issue_types(ev))
        self.assertNotIn("missing_vary", issue_types(ev))

    def test_star_echo_with_vary(self):
        ev = self.evaluate(acao="*", vary="Origin")
        self.assertIn("echo_wildcard_with_credentials", issue_types(ev))
        self.assertNotIn("missing_vary", issue_types(ev))

    def test_exact_echo_without_vary(self):
        ev = self.evaluate(acao="https://app.example.com")
        self.assertIn("missing_vary", issue_types(ev))
        self.assertNotIn("echo_wildcard_with_credentials", issue_types(ev))

    def test_star_echo_without_vary_reports_both(self):
        ev = self.evaluate(acao="*")
        self.assertIn("echo_wildcard_with_credentials", issue_types(ev))
        self.assertIn("missing_vary", issue_types(ev))

    def test_max_age_boundaries(self):
        self.assertIn("max_age_too_large", issue_types(self.evaluate(
            acao="https://app.example.com", vary="Origin", max_age="86401")))
        self.assertIn("max_age_negative", issue_types(self.evaluate(
            acao="https://app.example.com", vary="Origin", max_age="-1")))
        self.assertIn("max_age_invalid", issue_types(self.evaluate(
            acao="https://app.example.com", vary="Origin", max_age="soon")))

    def test_max_age_absent_and_boundary_ok(self):
        ev = self.evaluate(acao="https://app.example.com", vary="Origin")
        self.assertFalse(issue_types(ev) & {"max_age_too_large", "max_age_negative", "max_age_invalid"})
        ev = self.evaluate(acao="https://app.example.com", vary="Origin", max_age="86400")
        self.assertFalse(issue_types(ev) & {"max_age_too_large", "max_age_negative", "max_age_invalid"})


class Test09ReportFormatSortDedup(unittest.TestCase):
    """口径 9：报告字段、reason 约束、去重与排序。"""

    def build(self):
        rules = [
            make_rule("b-rule", ["https://app.example.com", "*.example.com"], methods=["GET"]),
            make_rule("a-rule", ["*"], credentials=True),
        ]
        requests = [make_request(method="DELETE")]
        return build_report(rules, requests)

    def test_evaluation_fields(self):
        report = self.build()
        for ev in report["evaluations"]:
            for field in ("rule_id", "allowed_methods", "credentials", "decision", "reason"):
                self.assertIn(field, ev)

    def test_empty_reason_only_without_issues(self):
        report = self.build()
        for ev in report["evaluations"]:
            if ev["issues"]:
                self.assertNotEqual(ev["reason"], "")
            else:
                self.assertEqual(ev["reason"], "")

    def test_dedup_same_rule_origin_type(self):
        # b-rule 的两条 origin 形态都命中同一请求，method_not_allowed 只出现一次
        report = self.build()
        keys = [(i["rule_id"], i["request_origin"], i["issue_type"]) for i in report["issues"]]
        self.assertEqual(len(keys), len(set(keys)))
        b_method = [k for k in keys if k[0] == "b-rule" and k[2] == "method_not_allowed"]
        self.assertEqual(len(b_method), 1)

    def test_sorted_by_rule_id_and_issue_type(self):
        report = self.build()
        eval_pairs = [(ev["rule_id"], ev["request_origin"]) for ev in report["evaluations"]]
        self.assertEqual(eval_pairs, sorted(eval_pairs))
        issue_keys = [(i["rule_id"], i["request_origin"], i["issue_type"]) for i in report["issues"]]
        self.assertEqual(issue_keys, sorted(issue_keys))
        for ev in report["evaluations"]:
            self.assertEqual(ev["issues"], sorted(ev["issues"]))

    def test_every_issue_has_reason(self):
        report = self.build()
        self.assertTrue(report["issues"])
        for issue in report["issues"]:
            self.assertTrue(issue["reason"])


class Test10MethodAndHeaderChecks(unittest.TestCase):
    """口径 10：方法与请求头大小写不敏感、分维度报告。"""

    def test_case_insensitive_positive(self):
        rule = make_rule(methods=["post"], headers=["content-type"])
        ev = evaluate_rule(rule, make_request(method="POST", request_headers=["Content-Type"]))
        self.assertNotIn("method_not_allowed", issue_types(ev))
        self.assertNotIn("header_not_allowed", issue_types(ev))

    def test_method_not_allowed(self):
        ev = evaluate_rule(make_rule(methods=["GET"]), make_request(method="DELETE"))
        self.assertIn("method_not_allowed", issue_types(ev))
        self.assertNotIn("header_not_allowed", issue_types(ev))

    def test_header_not_allowed_names_header(self):
        ev = evaluate_rule(make_rule(headers=["Content-Type"]),
                           make_request(request_headers=["X-Custom-Header"]))
        self.assertIn("header_not_allowed", issue_types(ev))
        self.assertNotIn("method_not_allowed", issue_types(ev))
        header_issue = next(i for i in ev.issues if i.issue_type == "header_not_allowed")
        self.assertIn("X-Custom-Header", header_issue.reason)

    def test_both_reported_as_two_issues(self):
        ev = evaluate_rule(make_rule(methods=["GET"], headers=["Content-Type"]),
                           make_request(method="DELETE", request_headers=["X-Custom-Header"]))
        self.assertIn("method_not_allowed", issue_types(ev))
        self.assertIn("header_not_allowed", issue_types(ev))
        self.assertEqual(len(ev.issues), 2)


class TestConfigParsing(unittest.TestCase):
    """配置解析：六个字段齐全，缺省有默认值。"""

    def test_full_parse(self):
        rule = make_rule(rule_id="r", origins=["*"], methods=["get"], headers=["X-A"],
                         credentials=True, max_age=100, exposed=["X-B"])
        self.assertEqual(rule.rule_id, "r")
        self.assertEqual(rule.allowed_origins, ["*"])
        self.assertEqual(rule.allowed_methods, ["get"])
        self.assertEqual(rule.allowed_headers, ["X-A"])
        self.assertEqual(rule.exposed_headers, ["X-B"])
        self.assertTrue(rule.allow_credentials)
        self.assertEqual(rule.max_age, 100)

    def test_defaults(self):
        rule = rule_from_dict({})
        self.assertEqual(rule.allowed_origins, [])
        self.assertFalse(rule.allow_credentials)
        self.assertIsNone(rule.max_age)

    def test_load_demo_rules(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "demo", "cors_rules.json")
        if os.path.exists(path):
            rules = load_rules(path)
            self.assertEqual(len(rules), 9)


if __name__ == "__main__":
    unittest.main()

