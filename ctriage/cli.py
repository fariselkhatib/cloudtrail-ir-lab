from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .loader import load, parse_time
from .report import to_json, to_markdown
from .rules import SEVERITY_ORDER, run_all


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ctriage", description="Triage CloudTrail logs for IR.")
    p.add_argument("paths", nargs="+", help="CloudTrail files or directories (.json, .json.gz, .jsonl)")
    p.add_argument("--since", help="ISO 8601 start time")
    p.add_argument("--until", help="ISO 8601 end time")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    p.add_argument("--md", help="Write Markdown report here (default: stdout)")
    p.add_argument("--json", help="Write JSON findings here")
    a = p.parse_args(argv)

    records = load(a.paths)
    if a.since:
        records = [r for r in records if parse_time(r["eventTime"]) >= parse_time(a.since)]
    if a.until:
        records = [r for r in records if parse_time(r["eventTime"]) <= parse_time(a.until)]
    findings = [f for f in run_all(records) if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[a.min_severity]]

    md = to_markdown(findings, records)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    elif not a.json:
        sys.stdout.write(md)
    if a.json:
        Path(a.json).write_text(to_json(findings, records), encoding="utf-8")
    print(f"{len(records)} events, {len(findings)} findings", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
