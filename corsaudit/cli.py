"""命令行入口：python -m corsaudit.cli --rules R --requests Q --out O"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional

from .config import load_requests, load_rules
from .report import build_report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="corsaudit",
        description="CORS 规则 / 请求 / 预检响应一致性审计器",
    )
    parser.add_argument("--rules", required=True, help="CORS 规则 JSON 文件路径")
    parser.add_argument("--requests", required=True, help="请求（含模拟预检响应）JSON 文件路径")
    parser.add_argument("--out", required=True, help="审计报告输出路径")
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)
    requests = load_requests(args.requests)
    report = build_report(rules, requests)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    summary = report["summary"]
    print(
        f"rules={summary['rules']} requests={summary['requests']} "
        f"evaluations={summary['evaluations']} issues={summary['issues']} "
        f"denied={summary['denied']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
