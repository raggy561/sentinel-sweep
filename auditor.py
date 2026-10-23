#!/usr/bin/env python3
"""
cloud-security-auditor — scans an AWS account for common misconfigurations.
Read-only by design: uses a profile backed by the SecurityAudit policy.
"""
import argparse
import json
import boto3
from datetime import datetime, timezone

# --- Read-only session -------------------------------------------------
# profile_name points at the read-only 'audit' credentials you configured.
# This tool NEVER creates, modifies, or deletes anything.
session = None

# A findings list collects everything we flag, so we can print one report
# at the end. Each finding is a dict: what service, how bad, the detail.
findings = []

def add_finding(service, severity, resource, detail):
    """Record one issue. Called by each check when it finds a problem."""
    findings.append({
        "service": service,
        "severity": severity,
        "resource": resource,
        "detail": detail,
    })


# --- Check 1: public S3 buckets ---------------------------------------
def check_s3_public_access():
    """Flag any bucket that doesn't have Block Public Access fully on."""
    s3 = session.client("s3")

    # list_buckets() returns a dict; the buckets live under the "Buckets" key.
    buckets = s3.list_buckets()["Buckets"]

    for bucket in buckets:
        name = bucket["Name"]
        try:
            # Ask AWS for this bucket's Block Public Access settings.
            resp = s3.get_public_access_block(Bucket=name)
            cfg = resp["PublicAccessBlockConfiguration"]

            # All four must be True for the bucket to be fully locked down.
            all_on = all([
                cfg["BlockPublicAcls"],
                cfg["IgnorePublicAcls"],
                cfg["BlockPublicPolicy"],
                cfg["RestrictPublicBuckets"],
            ])

            if not all_on:
                add_finding("S3", "HIGH", name,
                            "Block Public Access is not fully enabled")

        except s3.exceptions.ClientError as e:
            # If there's NO public access block at all, AWS raises this error.
            # No block = the bucket could be exposed = flag it.
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                add_finding("S3", "HIGH", name,
                            "No Block Public Access configuration set")
            else:
                # Some other error (permissions, etc.) — note it, don't crash.
                add_finding("S3", "INFO", name, f"Could not check: {e}")


# --- Report -----------------------------------------------------------
def print_report():
    print("\n" + "=" * 60)
    print("  CLOUD SECURITY AUDITOR — FINDINGS")
    print("=" * 60)

    if not findings:
        print("\n  No issues found. \n")
        return

    for f in findings:
        print(f"\n  [{f['severity']}] {f['service']} — {f['resource']}")
        print(f"        {f['detail']}")

    print(f"\n  {len(findings)} finding(s) total.\n")



    # --- Check 2: security groups open to the world ----------------------
def check_security_groups():
    """Flag ingress rules that allow 0.0.0.0/0 — worst on admin ports."""
    ec2 = session.client("ec2")

    # Ports we treat as especially dangerous if open to the whole internet.
    SENSITIVE = {22: "SSH", 3389: "RDP"}

    groups = ec2.describe_security_groups()["SecurityGroups"]

    for sg in groups:
        name = sg["GroupName"]
        gid  = sg["GroupId"]

        # IpPermissions = the inbound (ingress) rules on this group.
        for rule in sg["IpPermissions"]:
            proto     = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort")   # can be missing for "all"
            to_port   = rule.get("ToPort")

            # Is this rule open to the entire internet (IPv4 or IPv6)?
            open_v4 = any(r.get("CidrIp") == "0.0.0.0/0"
                          for r in rule.get("IpRanges", []))
            open_v6 = any(r.get("CidrIpv6") == "::/0"
                          for r in rule.get("Ipv6Ranges", []))
            if not (open_v4 or open_v6):
                continue   # not world-open — skip this rule

            # "-1" means ALL protocols / ALL ports open to the world.
            if proto == "-1":
                add_finding("EC2/SG", "HIGH", f"{name} ({gid})",
                            "ALL ports open to 0.0.0.0/0")
                continue

            # Does this rule's port range cover a sensitive admin port?
            hit = [svc for port, svc in SENSITIVE.items()
                   if from_port is not None and from_port <= port <= to_port]

            if hit:
                add_finding("EC2/SG", "HIGH", f"{name} ({gid})",
                            f"{', '.join(hit)} (ports {from_port}-{to_port}) "
                            f"open to 0.0.0.0/0")
            else:
                add_finding("EC2/SG", "MEDIUM", f"{name} ({gid})",
                            f"Ports {from_port}-{to_port} open to 0.0.0.0/0")


# --- Check 3: IAM users without MFA ----------------------------------
def check_iam_mfa():
    """Flag the root account and any console user with no MFA device."""
    iam = session.client("iam")

    # --- Half 1: root account MFA (via the account summary) ---
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) != 1:
        add_finding("IAM", "CRITICAL", "root account",
                    "Root account does NOT have MFA enabled")

    # --- Half 2: each IAM user with console access ---
    users = iam.list_users()["Users"]
    for user in users:
        username = user["UserName"]

        # Does this user have console access (a login profile)?
        # get_login_profile raises NoSuchEntity if they don't — a
        # programmatic-only (CLI key) user doesn't need MFA, so skip it.
        try:
            iam.get_login_profile(UserName=username)
        except iam.exceptions.NoSuchEntityException:
            continue   # no console login -> MFA not required

        # Console user: do they have any MFA device registered?
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        if not mfa_devices:
            add_finding("IAM", "HIGH", username,
                        "Console user has no MFA device")

# --- Check 4: stale access keys --------------------------------------
def check_stale_access_keys(max_age_days=90):
    """Flag IAM access keys older than max_age_days (default 90)."""
    iam = session.client("iam")
    now = datetime.now(timezone.utc)   # timezone-aware 'now' to compare against

    users = iam.list_users()["Users"]
    for user in users:
        username = user["UserName"]

        # Each user can have up to two access keys.
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            key_id  = key["AccessKeyId"]
            created = key["CreateDate"]       # AWS returns a tz-aware datetime
            status  = key["Status"]           # "Active" or "Inactive"

            # Subtracting two datetimes gives a timedelta; .days is the age.
            age = (now - created).days

            if age > max_age_days:
                add_finding("IAM", "MEDIUM", f"{username} / {key_id}",
                            f"Access key is {age} days old "
                            f"(>{max_age_days}d); status {status} — rotate it")

# --- Check 5: CloudTrail logging -------------------------------------
def check_cloudtrail():
    """Flag if no multi-region CloudTrail trail is actively logging."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]

    if not trails:
        add_finding("CloudTrail", "HIGH", "account",
                    "No CloudTrail trail configured — no audit logging")
        return

    # Is at least one multi-region trail actually logging right now?
    logging_multiregion = False
    for t in trails:
        if t.get("IsMultiRegionTrail"):
            status = ct.get_trail_status(Name=t["TrailARN"])
            if status.get("IsLogging"):
                logging_multiregion = True
                break

    if not logging_multiregion:
        add_finding("CloudTrail", "HIGH", "account",
                    "No multi-region trail is actively logging")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sentinel Sweep — read-only AWS security auditor")
    parser.add_argument("--profile", default="audit",
                        help="AWS CLI profile to use (default: audit)")
    args = parser.parse_args()

    # Create the read-only session from the chosen profile.
    session = boto3.Session(profile_name=args.profile)

    print(f"Running Sentinel Sweep (read-only) — profile '{args.profile}'...")
    check_s3_public_access()
    check_security_groups()
    check_iam_mfa()
    check_stale_access_keys()
    check_cloudtrail()
    print_report()

    import json   # add at top with the other imports

# Highest-to-lowest so the worst findings print first.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

def print_report():
    print("\n" + "=" * 60)
    print("  SENTINEL SWEEP — Cloud Security Auditor")
    print("=" * 60)

    if not findings:
        print("\n  No issues found against current checks.\n")
    else:
        # Print grouped by severity, worst first.
        for sev in SEVERITY_ORDER:
            for f in [x for x in findings if x["severity"] == sev]:
                print(f"\n  [{sev}] {f['service']} — {f['resource']}")
                print(f"        {f['detail']}")

        # One-line summary count, e.g. "1 CRITICAL, 2 HIGH, 1 MEDIUM".
        counts = {s: sum(1 for f in findings if f["severity"] == s)
                  for s in SEVERITY_ORDER}
        summary = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s])
        print("\n" + "-" * 60)
        print(f"  Summary: {summary}   ({len(findings)} total)")
        print("-" * 60)

    # Always write the machine-readable report for pipelines/automation.
    with open("findings.json", "w") as fh:
        json.dump(findings, fh, indent=2)
    print("\n  Full results written to findings.json\n")