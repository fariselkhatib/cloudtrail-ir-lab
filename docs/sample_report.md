# CloudTrail triage report

**Events analyzed:** 34  
**Window:** 2026-03-18T15:00:00Z to 2026-03-20T02:31:15Z  
**Findings:** 3 critical, 6 high, 2 medium

## Findings (chronological)

| Time (UTC) | Sev | Rule | Principal | Source IP | Event | Detail |
|---|---|---|---|---|---|---|
| 2026-03-18T15:00:00Z | high | CT-001 Root account activity | root | 203.0.113.5 | ConsoleLogin | mfa=Yes |
| 2026-03-20T02:10:03Z | high | CT-008 Long-lived access key used from new IP | ci-deployer | 198.51.100.23 | GetCallerIdentity | access_key=AKIAIOSFODNN7EXAMPLE; previous_ips=['203.0.113.50']; user_agent=aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0 exe/x86_64.ubuntu.22 |
| 2026-03-20T02:11:00Z | medium | CT-006 Burst of AccessDenied errors (permission enumeration) | ci-deployer | 198.51.100.23 | ListUsers | count=8; apis=['DescribeSnapshots', 'DescribeVpcs', 'GetAccountAuthorizationDetails', 'ListAccessKeys', 'ListAttachedUserPolicies', 'ListRoles', 'ListSecrets', 'ListUsers']; source_ips=['198.51.100.23'] |
| 2026-03-20T02:18:02Z | high | CT-004 IAM persistence: CreateUser | ci-deployer | 198.51.100.23 | CreateUser | target=svc-monitoring |
| 2026-03-20T02:19:10Z | critical | CT-005 Privileged managed policy attached | ci-deployer | 198.51.100.23 | AttachUserPolicy | target=svc-monitoring; policy=arn:aws:iam::aws:policy/AdministratorAccess |
| 2026-03-20T02:19:40Z | high | CT-004 IAM persistence: CreateAccessKey | ci-deployer | 198.51.100.23 | CreateAccessKey | target=svc-monitoring |
| 2026-03-20T02:21:05Z | critical | CT-003 Security logging disabled or modified | svc-monitoring | 198.51.100.23 | StopLogging |  |
| 2026-03-20T02:21:40Z | critical | CT-003 Security logging disabled or modified | svc-monitoring | 198.51.100.23 | DeleteDetector |  |
| 2026-03-20T02:25:00Z | high | CT-007 Bulk secret retrieval | svc-monitoring | 198.51.100.23 | GetSecretValue | distinct_secrets=6; secrets=['prod/db/master', 'prod/github/deploy-token', 'prod/jwt-signing', 'prod/smtp', 'prod/stripe/api', 'staging/db/master'] |
| 2026-03-20T02:30:00Z | high | CT-004 IAM persistence: CreateLoginProfile | svc-monitoring | 198.51.100.23 | CreateLoginProfile | target=svc-monitoring |
| 2026-03-20T02:31:15Z | medium | CT-002 Console login without MFA | svc-monitoring | 198.51.100.23 | ConsoleLogin |  |

## Recommended next steps

- **CT-005** (critical): Detach, then review every action taken by the target principal.
- **CT-003** (critical): Re-enable immediately. Treat everything after this timestamp as potentially unlogged.
- **CT-001** (high): Confirm with the account owner. Root should be break-glass only.
- **CT-008** (high): Compare user agent to the key's normal workload. Deactivate the key if unexplained.
- **CT-004** (high): Validate against change records. Disable new keys/users if unexplained.
- **CT-007** (high): Rotate every listed secret. Assume they are compromised.
- **CT-006** (medium): Identify where this credential is being used from and whether that IP is yours.
- **CT-002** (medium): Check whether this user should have a console password at all.

## Principals

| Principal | Events | Errors | Source IPs | First seen | Last seen | Flagged |
|---|---|---|---|---|---|---|
| ci-deployer | 19 | 8 | 198.51.100.23, 203.0.113.50 | 2026-03-19T20:00:00Z | 2026-03-20T02:19:40Z | yes |
| svc-monitoring | 10 | 0 | 198.51.100.23 | 2026-03-20T02:21:05Z | 2026-03-20T02:31:15Z | yes |
| alice | 4 | 2 | 203.0.113.60 | 2026-03-19T14:00:00Z | 2026-03-19T14:07:00Z |  |
| root | 1 | 0 | 203.0.113.5 | 2026-03-18T15:00:00Z | 2026-03-18T15:00:00Z | yes |
