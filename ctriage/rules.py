"""Detection rules for CloudTrail triage.

Each rule takes the full, time-sorted record list and returns Findings. Rules are written
to be read: an analyst should be able to defend every finding by pointing at the raw event.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .loader import actor, parse_time

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    mitre: str
    time: str
    actor: str
    source_ip: str
    event_name: str
    evidence: dict = field(default_factory=dict)
    event_ids: list[str] = field(default_factory=list)
    next_step: str = ""


def _f(rule_id, title, severity, mitre, r, evidence=None, next_step="", event_ids=None):
    return Finding(rule_id, title, severity, mitre, r["eventTime"], actor(r),
                   r.get("sourceIPAddress", ""), r["eventName"], evidence or {},
                   event_ids or [r.get("eventID", "")], next_step)


def _ok(r):
    return not r.get("errorCode")


# --- CT-001 ---------------------------------------------------------------
def root_usage(records):
    out = []
    for r in records:
        if (r.get("userIdentity") or {}).get("type") == "Root" and not (r.get("userIdentity") or {}).get("invokedBy"):
            out.append(_f("CT-001", "Root account activity", "high", "T1078.004", r,
                          {"mfa": (r.get("additionalEventData") or {}).get("MFAUsed", "n/a")},
                          "Confirm with the account owner. Root should be break-glass only."))
    return out


# --- CT-002 ---------------------------------------------------------------
def console_login_no_mfa(records):
    out = []
    for r in records:
        if r["eventName"] == "ConsoleLogin" and (r.get("responseElements") or {}).get("ConsoleLogin") == "Success" \
                and (r.get("additionalEventData") or {}).get("MFAUsed") == "No":
            out.append(_f("CT-002", "Console login without MFA", "medium", "T1078.004", r,
                          next_step="Check whether this user should have a console password at all."))
    return out


# --- CT-003 ---------------------------------------------------------------
LOGGING_TAMPER = {
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "DeleteFlowLogs", "DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount",
    "DeleteConfigurationRecorder", "StopConfigurationRecorder", "DisableSecurityHub",
}


def logging_tampering(records):
    return [_f("CT-003", "Security logging disabled or modified", "critical", "T1562.008", r,
               {"request": r.get("requestParameters")},
               "Re-enable immediately. Treat everything after this timestamp as potentially unlogged.")
            for r in records if r["eventName"] in LOGGING_TAMPER and _ok(r)]


# --- CT-004 / CT-005 ------------------------------------------------------
IAM_PERSISTENCE = {
    "CreateUser": "T1136.003", "CreateAccessKey": "T1098.001", "CreateLoginProfile": "T1098.001",
    "UpdateLoginProfile": "T1098.001", "AddUserToGroup": "T1098.003", "PutUserPolicy": "T1098.003",
    "AttachUserPolicy": "T1098.003", "AttachRolePolicy": "T1098.003", "PutRolePolicy": "T1098.003",
    "UpdateAssumeRolePolicy": "T1098.003", "CreateRole": "T1136.003",
}
ADMIN_POLICIES = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess")


def iam_persistence(records):
    out = []
    for r in records:
        if r["eventName"] not in IAM_PERSISTENCE or not _ok(r):
            continue
        req = r.get("requestParameters") or {}
        policy = req.get("policyArn", "")
        if policy.endswith(ADMIN_POLICIES):
            out.append(_f("CT-005", "Privileged managed policy attached", "critical", "T1098.003", r,
                          {"target": req.get("userName") or req.get("roleName") or req.get("groupName"),
                           "policy": policy},
                          "Detach, then review every action taken by the target principal."))
            continue
        target = req.get("userName") or req.get("roleName") or ""
        out.append(_f("CT-004", f"IAM persistence: {r['eventName']}", "high", IAM_PERSISTENCE[r["eventName"]], r,
                      {"target": target},
                      "Validate against change records. Disable new keys/users if unexplained."))
    return out


# --- CT-006 ---------------------------------------------------------------
def access_denied_burst(records, threshold=5, window=timedelta(minutes=15)):
    """Many authorization failures from one principal in a short window: classic
    enumeration with a stolen credential that doesn't know its own permissions yet."""
    by_actor = defaultdict(list)
    for r in records:
        if r.get("errorCode") in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"):
            by_actor[actor(r)].append(r)
    out = []
    for who, evs in by_actor.items():
        start = 0
        for end in range(len(evs)):
            while parse_time(evs[end]["eventTime"]) - parse_time(evs[start]["eventTime"]) > window:
                start += 1
            if end - start + 1 >= threshold:
                t0 = parse_time(evs[start]["eventTime"])
                burst = [e for e in evs[start:] if parse_time(e["eventTime"]) - t0 <= window]
                out.append(_f("CT-006", "Burst of AccessDenied errors (permission enumeration)", "medium", "T1580",
                              evs[start],
                              {"count": len(burst), "apis": sorted({e["eventName"] for e in burst}),
                               "source_ips": sorted({e.get("sourceIPAddress", "") for e in burst})},
                              "Identify where this credential is being used from and whether that IP is yours.",
                              [e.get("eventID", "") for e in burst]))
                break
    return out


# --- CT-007 ---------------------------------------------------------------
SECRET_READS = {"GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath"}


def secrets_harvesting(records, threshold=3, window=timedelta(minutes=30)):
    by_actor = defaultdict(list)
    for r in records:
        if r["eventName"] in SECRET_READS and _ok(r):
            by_actor[actor(r)].append(r)
    out = []
    for who, evs in by_actor.items():
        first = parse_time(evs[0]["eventTime"])
        in_win = [e for e in evs if parse_time(e["eventTime"]) - first <= window]
        names = sorted({(e.get("requestParameters") or {}).get("secretId")
                        or (e.get("requestParameters") or {}).get("name", "?") for e in in_win})
        if len(names) >= threshold:
            out.append(_f("CT-007", "Bulk secret retrieval", "high", "T1555.006", evs[0],
                          {"distinct_secrets": len(names), "secrets": names},
                          "Rotate every listed secret. Assume they are compromised.",
                          [e.get("eventID", "") for e in in_win]))
    return out


# --- CT-008 ---------------------------------------------------------------
def new_source_ip_for_principal(records, baseline=timedelta(days=1)):
    """Flags the first time a long-lived IAM user key is used from an IP that the key never
    used in the preceding baseline. Only evaluated for principals with baseline activity."""
    out, history = [], defaultdict(list)
    for r in records:
        ui = r.get("userIdentity") or {}
        if ui.get("type") != "IAMUser" or r.get("eventType") == "AwsConsoleSignIn":
            continue
        key = ui.get("accessKeyId", "")
        if not key.startswith("AKIA"):
            continue
        t, ip = parse_time(r["eventTime"]), r.get("sourceIPAddress", "")
        prior = [(pt, pip) for pt, pip in history[key] if t - pt <= baseline]
        if prior and ip not in {pip for _, pip in prior} and ip not in {pip for _, pip in history[key]}:
            out.append(_f("CT-008", "Long-lived access key used from new IP", "high", "T1078.004", r,
                          {"access_key": key, "previous_ips": sorted({pip for _, pip in history[key]}),
                           "user_agent": r.get("userAgent", "")},
                          "Compare user agent to the key's normal workload. Deactivate the key if unexplained."))
        history[key].append((t, ip))
    return out


ALL_RULES = [root_usage, console_login_no_mfa, logging_tampering, iam_persistence,
             access_denied_burst, secrets_harvesting, new_source_ip_for_principal]


def run_all(records) -> list[Finding]:
    findings = [f for rule in ALL_RULES for f in rule(records)]
    findings.sort(key=lambda f: (f.time, SEVERITY_ORDER[f.severity]))
    return findings
