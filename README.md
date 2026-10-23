# Sentinel Sweep — Cloud Security Auditor (Python + boto3)

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-232F3E?logo=amazonaws&logoColor=white)
![CSPM](https://img.shields.io/badge/Cloud_Security-Posture-0FB39A)

A Python tool that scans an AWS account for common security misconfigurations and produces a clear, severity-ranked findings report. A lightweight, readable take on cloud security posture management (CSPM).

> Demonstrates security automation: turning "things a cloud security engineer checks by hand" into repeatable, auditable code — read-only by design.

---

## What it checks

- **S3** — buckets without Block Public Access fully enabled
- **Security groups** — ingress rules open to `0.0.0.0/0` (or `::/0`), flagged HIGH on admin ports (SSH 22, RDP 3389)
- **IAM — MFA** — the root account without MFA, and any console user with no MFA device
- **IAM — access keys** — keys older than 90 days (rotation overdue)
- **CloudTrail** — no trail configured, or no multi-region trail actively logging

## Output

Two outputs from a single run:
- **Console summary** — findings grouped worst-first, with a one-line severity count
- **`findings.json`** — structured results for pipelines/automation (git-ignored; may contain account identifiers)

```
============================================================
  SENTINEL SWEEP — Cloud Security Auditor
============================================================

  [CRITICAL] IAM — root account
        Root account does NOT have MFA enabled

  [HIGH] EC2/SG — open-web-sg (sg-0abc123)
        SSH (ports 22-22) open to 0.0.0.0/0

  [MEDIUM] IAM — svc-deploy / AKIA...EXAMPLE
        Access key is 412 days old (>90d); status Active — rotate it

------------------------------------------------------------
  Summary: 1 CRITICAL, 1 HIGH, 1 MEDIUM   (3 total)
------------------------------------------------------------
```

---

## Security decisions

| Choice | Decision | Why |
|--------|----------|-----|
| Read-only | Backed by the AWS-managed **`SecurityAudit`** policy on a dedicated IAM user | An auditor should never be able to change what it audits — enforced by AWS itself, not just code |
| No hardcoded creds | Uses the AWS credential chain via a named profile (`--profile`) | Secrets never live in the repo; `.tfvars`-style discipline |
| Severity model | Findings ranked CRITICAL / HIGH / MEDIUM / LOW | Focuses remediation on what matters first |
| Extensible checks | Each control is a self-contained `check_*()` function appending to a shared findings list | New controls drop in without touching existing ones |
| Fail-open on errors | Permission/API errors are recorded as INFO, never crash the scan | A missing permission shouldn't hide the findings it *can* collect |

---

## How to run

**Prerequisites:** Python 3.10+, an AWS account, and the AWS CLI configured with a **read-only** profile (an IAM user carrying the `SecurityAudit` managed policy).

```bash
git clone https://github.com/<your-username>/cloud-security-auditor.git
cd cloud-security-auditor
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python auditor.py                     # uses the 'audit' profile by default
python auditor.py --profile prod      # or point at any configured profile
```

---

## Scope & design notes

- **Regional vs global.** IAM, S3 (bucket listing), and the account-level CloudTrail view are global/account-wide; **security groups are regional**, so that check covers the profile's configured region only. Multi-region SG scanning is on the roadmap.
- **Read-only, always.** No `create`, `put`, `delete`, or `modify` calls exist in the codebase — by design and by IAM policy.

## Roadmap

- Multi-region security-group scanning (loop over all regions)
- S3 encryption-at-rest and bucket-policy checks
- IAM "unused credentials" (last-used age) and password-policy checks
- HTML report output in addition to JSON
- Package as a GitHub Action to run on a schedule

---

## What I learned

- **boto3 error handling is part of the logic, not just safety.** For IAM MFA, `get_login_profile` *raising* `NoSuchEntityException` is the signal that a user is programmatic-only — the exception is the answer, not a failure. Leaning on `try/except` as control flow was the mental shift.
- **Timezone-aware datetimes matter.** AWS returns tz-aware timestamps; Python refuses to subtract a naive `datetime` from them, so access-key age has to be computed against `datetime.now(timezone.utc)`.
- **Precision is the whole point of an auditor.** The tool returns clean against my own hardened Terradome landing zone (/32 security group, Block Public Access on, multi-region trail logging) and only flags genuine gaps — a scanner that cries wolf on everything is worthless.

---

**Hansley Jean** — Cloud Security Engineer
AWS Certified Security – Specialty · HashiCorp Certified: Terraform Associate · Microsoft Certified: Azure Security Engineer (AZ-500)
[LinkedIn](https://linkedin.com/in/hansley-j-0522711b9) · [GitHub](https://github.com/raggy561)
