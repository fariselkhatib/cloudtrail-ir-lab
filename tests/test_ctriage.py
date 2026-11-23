import gzip
import json
from pathlib import Path

import pytest

from ctriage.cli import main
from ctriage.loader import actor, load
from ctriage.report import principal_summary, to_markdown
from ctriage.rules import run_all

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "cloudtrail_sample.json"


@pytest.fixture(scope="module")
def records():
    return load([SAMPLE])


@pytest.fixture(scope="module")
def findings(records):
    return run_all(records)


def by_rule(findings, rule):
    return [f for f in findings if f.rule_id == rule]


# --- loader ---------------------------------------------------------------

def test_loads_and_sorts(records):
    assert len(records) == 34
    times = [r["eventTime"] for r in records]
    assert times == sorted(times)


def test_loads_jsonl_gz_and_dedupes(tmp_path, records):
    p = tmp_path / "events.jsonl.gz"
    with gzip.open(p, "wt") as fh:
        for r in records[:5] + records[:5]:  # duplicates on purpose
            fh.write(json.dumps(r) + "\n")
    from ctriage.loader import load_file
    assert len(load_file(p)) == 10          # raw file keeps duplicates
    (tmp_path / "a.json").write_text(json.dumps(records[:5]))
    (tmp_path / "b.json").write_text(json.dumps({"Records": records[:5]}))
    assert len(load([tmp_path])) == 5       # directory load dedupes across all three formats


def test_actor_resolution():
    assert actor({"userIdentity": {"type": "Root"}}) == "root"
    assert actor({"userIdentity": {"type": "AssumedRole",
                                   "arn": "arn:aws:sts::111122223333:assumed-role/Admin/alice"}}) == "Admin/alice"
    assert actor({"userIdentity": {"type": "IAMUser", "userName": "bob"}}) == "bob"


# --- rules: the attack chain is detected -----------------------------------

def test_leaked_key_new_ip(findings):
    f = by_rule(findings, "CT-008")
    assert len(f) == 1
    assert f[0].actor == "ci-deployer" and f[0].source_ip == "198.51.100.23"
    assert f[0].event_name == "GetCallerIdentity"


def test_enumeration_burst(findings):
    f = by_rule(findings, "CT-006")
    assert len(f) == 1 and f[0].actor == "ci-deployer" and f[0].evidence["count"] == 8


def test_alice_two_denials_not_a_burst(findings):
    assert not [f for f in by_rule(findings, "CT-006") if f.actor == "alice"]


def test_iam_persistence_and_admin_policy(findings):
    assert {f.event_name for f in by_rule(findings, "CT-004")} == {"CreateUser", "CreateAccessKey", "CreateLoginProfile"}
    admin = by_rule(findings, "CT-005")
    assert len(admin) == 1 and admin[0].evidence["target"] == "svc-monitoring"
    assert admin[0].severity == "critical"


def test_logging_tamper(findings):
    assert {f.event_name for f in by_rule(findings, "CT-003")} == {"StopLogging", "DeleteDetector"}


def test_secrets_harvest(findings):
    f = by_rule(findings, "CT-007")
    assert len(f) == 1 and f[0].evidence["distinct_secrets"] == 6


def test_console_no_mfa_only_flags_backdoor_user(findings):
    f = by_rule(findings, "CT-002")
    assert [x.actor for x in f] == ["svc-monitoring"]


def test_root_flagged_even_with_mfa(findings):
    f = by_rule(findings, "CT-001")
    assert len(f) == 1 and f[0].evidence["mfa"] == "Yes"


def test_failed_calls_do_not_count_as_persistence(records):
    tweaked = [dict(r) for r in records]
    for r in tweaked:
        if r["eventName"] == "CreateUser":
            r["errorCode"] = "AccessDenied"
    assert not [f for f in run_all(tweaked) if f.event_name == "CreateUser"]


def test_benign_baseline_is_quiet(records):
    baseline = [r for r in records if r["eventTime"] < "2026-03-20" and r["userIdentity"]["type"] != "Root"]
    assert run_all(baseline) == []


# --- report / cli ---------------------------------------------------------

def test_principal_summary(records):
    s = {p["principal"]: p for p in principal_summary(records)}
    assert s["ci-deployer"]["source_ips"] == ["198.51.100.23", "203.0.113.50"]
    assert s["svc-monitoring"]["errors"] == 0


def test_markdown_report(records, findings):
    md = to_markdown(findings, records)
    assert "3 critical" in md and "CT-005" in md and "Recommended next steps" in md


def test_cli(tmp_path):
    md, js = tmp_path / "r.md", tmp_path / "f.json"
    assert main([str(SAMPLE), "--md", str(md), "--json", str(js), "--min-severity", "high"]) == 0
    data = json.loads(js.read_text())
    assert all(f["severity"] in ("critical", "high") for f in data["findings"])
    assert len(data["findings"]) == 9


def test_cli_time_filter(tmp_path):
    js = tmp_path / "f.json"
    main([str(SAMPLE), "--since", "2026-03-20T02:20:00Z", "--json", str(js)])
    data = json.loads(js.read_text())
    assert {f["actor"] for f in data["findings"]} == {"svc-monitoring"}
