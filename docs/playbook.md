# Response playbook: leaked IAM access key

Scenario this lab models: a long-lived IAM user key leaks (CI logs, public repo, compromised laptop), an attacker enumerates, creates a backdoor admin user, blinds logging, and pulls secrets.

Times below are relative to when you confirm the key is being misused (T0).

## 1. Scope (T0 to T0+30m)

Goal: know which principals are involved before you start pulling keys, so you don't tip off the actor and leave a second door open.

- [ ] Run `ctriage` across the full available window, not just the alert window. Persistence often predates the alert.
- [ ] From the **Principals** table, list every principal that touched an attacker IP. Pivot: search CloudTrail for each attacker IP across *all* principals.
- [ ] List every IAM object the compromised principal created or modified (`CT-004`, `CT-005` targets). Each one is now a suspect principal; repeat the pivot.
- [ ] Check `CT-003`. If logging was stopped, note the exact time. Anything after it may be missing from CloudTrail; lean on GuardDuty history, VPC Flow Logs, S3 server access logs, and service-specific logs.
- [ ] Check other regions. A trail that isn't multi-region can miss activity elsewhere.

## 2. Contain (T0+30m to T0+1h)

Do these in one sitting, in this order:

1. **Restore visibility.** Re-enable the trail and GuardDuty first, so containment actions are logged.
2. **Deactivate, don't delete.** Set the leaked key and every attacker-created key to `Inactive`. Deleting destroys evidence you may need.
3. **Neutralize backdoor principals.** Detach policies, delete login profiles, attach an explicit deny-all inline policy. Keep the users for now.
4. **Revoke sessions.** For any role the attacker assumed, use "Revoke active sessions" (adds a deny for tokens issued before now). STS credentials survive key deactivation otherwise.
5. **Rotate secrets** listed in `CT-007`. Rotate at the source (database password, third-party API key), not just in Secrets Manager.

## 3. Investigate (T0+1h onward)

- [ ] For each harvested secret: what does it unlock? Check that downstream system's logs for use from attacker IPs.
- [ ] Data access: S3 `GetObject` requires data events. If they weren't enabled, say so plainly in the report rather than implying no access occurred.
- [ ] Compute: look for `RunInstances`, `CreateFunction`, `ImportKeyPair`, new security group ingress. Crypto-mining is a common follow-on.
- [ ] Root cause: where did the key leak? Search code repos and CI logs for the key ID.

## 4. Recover and harden

- Replace long-lived CI keys with OIDC federation / IAM roles.
- SCP to deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:DeleteDetector` for everyone except a break-glass role.
- Alert on `CreateUser`, `CreateAccessKey`, and `AttachUserPolicy` with admin policies.
- Enforce MFA for console access via IAM policy conditions.

## Reporting

State what the logs establish, what they don't, and why. Example:

> CloudTrail establishes that `svc-monitoring` retrieved six secrets at 02:25 UTC. CloudTrail management events do not record S3 object reads in this account, so we cannot confirm or rule out data access from S3 during the same period.
