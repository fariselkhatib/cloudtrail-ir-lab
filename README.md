# cloudtrail-ir-lab

![tests](https://github.com/fariselkhatib/cloudtrail-ir-lab/actions/workflows/tests.yml/badge.svg)

A CloudTrail triage tool and response playbook for the AWS incident you're most likely to actually work: a leaked IAM access key. Point it at a pile of CloudTrail logs, get a chronological findings report with ATT&CK mapping, a per-principal summary, and next steps.

## The problem

When an AWS key leaks, the first hour is spent answering the same questions: where is the key being used from, what did it try, what did it create, did it blind logging, what did it read. CloudTrail has the answers, but raw JSON across dozens of gzipped files isn't something you can hand to an incident commander.

## What it detects

| Rule | Finding | Severity | ATT&CK |
|---|---|---|---|
| CT-001 | Root account activity | high | T1078.004 |
| CT-002 | Console login without MFA | medium | T1078.004 |
| CT-003 | CloudTrail / GuardDuty / Config disabled or modified | critical | T1562.008 |
| CT-004 | IAM persistence (new users, keys, login profiles, inline policies) | high | T1136.003, T1098.001, T1098.003 |
| CT-005 | Admin-level managed policy attached | critical | T1098.003 |
| CT-006 | Burst of AccessDenied errors (permission enumeration) | medium | T1580 |
| CT-007 | Bulk retrieval from Secrets Manager / Parameter Store | high | T1555.006 |
| CT-008 | Long-lived access key used from a new IP | high | T1078.004 |

Failed API calls never count as persistence or tampering. Every finding carries the raw `eventID`s so you can pull the exact source records for the report.

## Data source

`samples/cloudtrail_sample.json` is **synthetic**, using AWS's documentation account ID (`111122223333`), AWS example key IDs, and RFC 5737 IPs. It contains a quiet baseline (normal CI activity, a user with a couple of harmless denials, a root login with MFA) followed by the attack:

1. Leaked `ci-deployer` key used from a new IP with a different user agent
2. `GetCallerIdentity`, then 8 `AccessDenied` calls while enumerating
3. Creates `svc-monitoring`, attaches `AdministratorAccess`, issues it an access key
4. As `svc-monitoring`: stops CloudTrail, deletes the GuardDuty detector
5. Pulls 6 secrets, creates a console password, logs in without MFA

To run against real logs from your own sandbox account, see [docs/sandbox-setup.md](docs/sandbox-setup.md).

## How to run

Python 3.10+, no dependencies.

```bash
git clone https://github.com/fariselkhatib/cloudtrail-ir-lab.git
cd cloudtrail-ir-lab

python -m ctriage samples/cloudtrail_sample.json --md report.md --json findings.json
```

Accepts files or directories of `.json`, `.json.gz`, `.jsonl`, `.jsonl.gz` (native CloudTrail delivery format, bare arrays, or JSON Lines from CloudTrail Lake / Athena / SIEM exports). Duplicate events are dropped by `eventID`.

| Flag | What it does |
|---|---|
| `--since` / `--until` | Scope to a window (ISO 8601) |
| `--min-severity` | Drop findings below `critical` / `high` / `medium` / `low` |
| `--md` / `--json` | Output paths (Markdown defaults to stdout) |

Tests:

```bash
pip install pytest
python -m pytest -q
```

## Sample output

From [docs/sample_report.md](docs/sample_report.md):

| Time (UTC) | Sev | Rule | Principal | Source IP | Event |
|---|---|---|---|---|---|
| 2026-03-20T02:10:03Z | high | CT-008 Long-lived access key used from new IP | ci-deployer | 198.51.100.23 | GetCallerIdentity |
| 2026-03-20T02:11:00Z | medium | CT-006 Burst of AccessDenied errors | ci-deployer | 198.51.100.23 | ListUsers |
| 2026-03-20T02:18:02Z | high | CT-004 IAM persistence: CreateUser | ci-deployer | 198.51.100.23 | CreateUser |
| 2026-03-20T02:19:10Z | critical | CT-005 Privileged managed policy attached | ci-deployer | 198.51.100.23 | AttachUserPolicy |
| 2026-03-20T02:21:05Z | critical | CT-003 Security logging disabled or modified | svc-monitoring | 198.51.100.23 | StopLogging |
| 2026-03-20T02:25:00Z | high | CT-007 Bulk secret retrieval | svc-monitoring | 198.51.100.23 | GetSecretValue |
| 2026-03-20T02:31:15Z | medium | CT-002 Console login without MFA | svc-monitoring | 198.51.100.23 | ConsoleLogin |

The baseline activity produces zero findings, which is tested.

## Response playbook

[docs/playbook.md](docs/playbook.md) walks through scope, contain, investigate, and harden for this scenario, including the order of containment steps (restore logging first, deactivate rather than delete, revoke STS sessions) and how to write up what the logs can and can't establish.

## Limitations

- **Management events only.** S3 object reads, Lambda invocations, and DynamoDB item access require CloudTrail data events, which most accounts don't enable. No finding here means "not in management events," not "didn't happen."
- **CT-008 needs a baseline.** A key with no prior activity in the loaded logs can't be "new IP." Load at least a day before the suspected compromise.
- **No IP enrichment.** No ASN, geo, or threat intel lookups. Add your own before drawing conclusions from an IP.
- **Thresholds are fixed defaults.** Burst and harvesting thresholds suit a small account. Busy accounts will need tuning in `ctriage/rules.py`.
- **In-memory.** Fine for an incident window; for months of org-wide logs use Athena or CloudTrail Lake and export the slice.
- **Not a replacement for GuardDuty.** This is post-incident triage, not real-time detection.

## License

MIT. See [LICENSE](LICENSE).
