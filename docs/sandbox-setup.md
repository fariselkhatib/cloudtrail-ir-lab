# Running against your own sandbox

The bundled sample is synthetic. To test against real CloudTrail output:

1. **Use a dedicated, self-owned AWS account** with nothing in it you care about. Never a work or client account.
2. Enable a multi-region CloudTrail trail delivering to an S3 bucket in that account.
3. Generate activity. Options:
   - Do it by hand with a throwaway IAM user: a few `AccessDenied` calls, `CreateUser`, `AttachUserPolicy`, `StopLogging` (then re-enable).
   - Use an attack emulation tool built for this, such as Stratus Red Team, which detonates and cleans up specific ATT&CK techniques in AWS.
4. Wait 5 to 15 minutes for delivery, then sync logs locally:
   ```bash
   aws s3 sync s3://YOUR-TRAIL-BUCKET/AWSLogs/ ./logs/
   python -m ctriage ./logs --md report.md
   ```
5. **Clean up**: delete test users and keys, and confirm logging is back on.

## Before you commit anything

- No real account IDs, ARNs, access key IDs, or IPs. Replace with `111122223333`, `AKIA...EXAMPLE`, and RFC 5737 ranges.
- No log files from any account you don't personally own.
- `.gitignore` excludes `logs/`, `findings.*`, and generated reports by default.
