from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict

from .loader import actor
from .rules import SEVERITY_ORDER, Finding


def principal_summary(records) -> list[dict]:
    agg = defaultdict(lambda: {"events": 0, "errors": 0, "ips": set(), "first": None, "last": None,
                               "top_apis": Counter()})
    for r in records:
        a = agg[actor(r)]
        a["events"] += 1
        a["errors"] += bool(r.get("errorCode"))
        a["ips"].add(r.get("sourceIPAddress", ""))
        a["first"] = a["first"] or r["eventTime"]
        a["last"] = r["eventTime"]
        a["top_apis"][r["eventName"]] += 1
    return [{"principal": k, "events": v["events"], "errors": v["errors"], "source_ips": sorted(v["ips"]),
             "first_seen": v["first"], "last_seen": v["last"],
             "top_apis": [n for n, _ in v["top_apis"].most_common(5)]}
            for k, v in sorted(agg.items(), key=lambda kv: -kv[1]["events"])]


def to_json(findings: list[Finding], records) -> str:
    return json.dumps({"findings": [asdict(f) for f in findings],
                       "principals": principal_summary(records)}, indent=2)


def to_markdown(findings: list[Finding], records) -> str:
    sev = Counter(f.severity for f in findings)
    flagged = sorted({f.actor for f in findings})
    lines = [
        "# CloudTrail triage report", "",
        f"**Events analyzed:** {len(records)}  ",
        f"**Window:** {records[0]['eventTime'] if records else '-'} to {records[-1]['eventTime'] if records else '-'}  ",
        "**Findings:** " + ", ".join(f"{sev[s]} {s}" for s in SEVERITY_ORDER if sev[s]) if findings else "**Findings:** none",
        "", "## Findings (chronological)", "",
        "| Time (UTC) | Sev | Rule | Principal | Source IP | Event | Detail |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        detail = "; ".join(f"{k}={v}" for k, v in f.evidence.items() if k != "request" and v not in (None, ""))
        lines.append(f"| {f.time} | {f.severity} | {f.rule_id} {f.title} | {f.actor} | {f.source_ip} | "
                     f"{f.event_name} | {detail.replace('|', '/')} |")
    lines += ["", "## Recommended next steps", ""]
    seen = set()
    for f in sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity]):
        if f.rule_id not in seen and f.next_step:
            seen.add(f.rule_id)
            lines.append(f"- **{f.rule_id}** ({f.severity}): {f.next_step}")
    lines += ["", "## Principals", "", "| Principal | Events | Errors | Source IPs | First seen | Last seen | Flagged |",
              "|---|---|---|---|---|---|---|"]
    for p in principal_summary(records):
        lines.append(f"| {p['principal']} | {p['events']} | {p['errors']} | {', '.join(p['source_ips'])} | "
                     f"{p['first_seen']} | {p['last_seen']} | {'yes' if p['principal'] in flagged else ''} |")
    return "\n".join(lines) + "\n"
