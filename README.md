# Sentinel Sweep - The Cloud Security Auditor (Python + boto3)

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-232F3E?logo=amazonaws&logoColor=white)
![CSPM](https://img.shields.io/badge/Cloud_Security-Posture-0FB39A)

A Python tool that scans an AWS account for common security misconfigurations and produces a clear findings report. A lightweight, readable take on cloud security posture management (CSPM).

> Demonstrates security automation: turning "things a cloud security engineer checks by hand" into repeatable, auditable code.

---

## What it checks
<!-- Adjust to match what you actually build; start small, expand -->
- **S3** — publicly accessible buckets, missing encryption, no public-access block
- **Security groups** — rules open to `0.0.0.0/0` on sensitive ports
- **IAM** — users without MFA, access keys older than <!-- N --> days, unused credentials
- **Logging** — CloudTrail disabled or not multi-region
<!-- Add your own checks -->

## Output
Produces both a machine-readable and a human-readable report:
- `findings.json` — structured results for pipelines/automation
- Console summary — grouped by severity, readable at a glance

```
<!-- paste a sample of your actual output here once it runs -->
[ HIGH ] S3 bucket 'example-bucket' is publicly accessible
[ MED  ] IAM user 'svc-deploy' has an access key 412 days old
...
Summary: 3 HIGH, 5 MEDIUM, 2 LOW
```

---

## Security decisions
| Choice | Decision | Why |
|--------|----------|-----|
| Read-only | Tool uses least-privilege, read-only AWS permissions | An auditor should never be able to change what it audits |
| Severity model | Findings ranked HIGH / MED / LOW | Focuses remediation on what matters first |
| No hardcoded creds | Uses the AWS credential chain / profiles | Never embed secrets in code |
| Extensible checks | Each check is a self-contained function/module | Easy to add controls as the threat model grows |
<!-- Edit to match your implementation -->

---

## How to run
**Prerequisites:** Python >= 3.<!-- x -->, AWS CLI configured with **read-only** credentials, `boto3` installed.

```bash
git clone https://github.com/<your-username>/cloud-security-auditor.git
cd cloud-security-auditor
pip install -r requirements.txt
python auditor.py --profile <your-aws-profile>
```

---

## What I learned
<!-- Honest notes: an AWS API quirk, a false-positive you had to tune out, how you structured checks. Shows real depth. -->
-
-

---

**Hansley Jean** — Cloud Security Engineer
AWS Certified Security – Specialty · Microsoft Certified: Azure Security Engineer (AZ-500)
[LinkedIn](https://linkedin.com/in/hansley-j-0522711b9) · [GitHub](https://github.com/<your-username>)
