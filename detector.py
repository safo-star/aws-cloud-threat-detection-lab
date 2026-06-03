import json
from collections import defaultdict


def load_logs(file_path="cloud_logs.json"):
    with open(file_path, "r") as file:
        return json.load(file)


def analyze_cloud_logs(logs):
    alerts = []

    failed_login_tracker = defaultdict(list)

    for log in logs:
        event_name = log.get("eventName", "")
        user = log.get("userIdentity", "Unknown")
        source_ip = log.get("sourceIPAddress", "Unknown")
        timestamp = log.get("timestamp", "Unknown")
        event_source = log.get("eventSource", "Unknown")

        # Track failed logins
        if event_name == "ConsoleLogin" and log.get("errorMessage") == "Failed authentication":
            failed_login_tracker[(user, source_ip)].append(timestamp)

        # Successful login without MFA
        if event_name == "ConsoleLogin" and log.get("responseElements") == "Success":
            if log.get("mfaUsed") is False:
                alerts.append(create_alert(
                    timestamp,
                    "Successful Login Without MFA",
                    "High",
                    75,
                    user,
                    source_ip,
                    event_source,
                    "A successful console login occurred without MFA enabled.",
                    "Require MFA for all users, especially admin and root accounts."
                ))

        # Root account usage
        if user.lower() == "root":
            alerts.append(create_alert(
                timestamp,
                "Root Account Usage",
                "Critical",
                95,
                user,
                source_ip,
                event_source,
                "The AWS root account was used. Root account usage is high risk.",
                "Avoid using the root account. Enable MFA and use IAM roles/users instead."
            ))

        # MFA disabled
        if event_name == "DeactivateMFADevice":
            alerts.append(create_alert(
                timestamp,
                "MFA Disabled",
                "Critical",
                90,
                user,
                source_ip,
                event_source,
                "An MFA device was deactivated for a cloud account.",
                "Investigate immediately and re-enable MFA."
            ))

        # Admin policy attached
        if event_name == "AttachUserPolicy" and log.get("policyName") == "AdministratorAccess":
            alerts.append(create_alert(
                timestamp,
                "Administrator Policy Attached",
                "Critical",
                90,
                user,
                source_ip,
                event_source,
                "AdministratorAccess policy was attached to a user.",
                "Review whether this permission is approved and remove excessive privileges."
            ))

        # Access key created
        if event_name == "CreateAccessKey":
            alerts.append(create_alert(
                timestamp,
                "Access Key Created",
                "High",
                80,
                user,
                source_ip,
                event_source,
                "A new AWS access key was created.",
                "Confirm the key was created by an authorized user and rotate if suspicious."
            ))

        # Public S3 bucket policy
        if event_name == "PutBucketPolicy" and log.get("publicAccess") is True:
            alerts.append(create_alert(
                timestamp,
                "S3 Bucket Made Public",
                "Critical",
                95,
                user,
                source_ip,
                event_source,
                "A bucket policy allowed public access to an S3 bucket.",
                "Block public access and review bucket policy permissions."
            ))

        # Large S3 download
        if event_name == "GetObject" and log.get("bytesDownloaded", 0) >= 500000000:
            alerts.append(create_alert(
                timestamp,
                "Large S3 Data Download",
                "High",
                85,
                user,
                source_ip,
                event_source,
                "A large amount of data was downloaded from S3.",
                "Investigate for possible data exfiltration."
            ))

        # CloudTrail stopped
        if event_name == "StopLogging":
            alerts.append(create_alert(
                timestamp,
                "CloudTrail Logging Stopped",
                "Critical",
                100,
                user,
                source_ip,
                event_source,
                "CloudTrail logging was stopped, reducing visibility into cloud activity.",
                "Re-enable CloudTrail immediately and investigate the user."
            ))

    # Failed login burst detection
    for (user, source_ip), timestamps in failed_login_tracker.items():
        if len(timestamps) >= 3:
            alerts.append(create_alert(
                timestamps[-1],
                "Failed Login Burst",
                "Medium",
                60,
                user,
                source_ip,
                "signin.amazonaws.com",
                f"{len(timestamps)} failed login attempts were detected from the same IP.",
                "Review the source IP, lock the account if needed, and enforce MFA."
            ))

    return sorted(alerts, key=lambda alert: alert["risk_score"], reverse=True)


def create_alert(timestamp, alert_name, severity, risk_score, user, source_ip, event_source, description, recommendation):
    return {
        "timestamp": timestamp,
        "alert_name": alert_name,
        "severity": severity,
        "risk_score": risk_score,
        "user": user,
        "source_ip": source_ip,
        "event_source": event_source,
        "description": description,
        "recommendation": recommendation
    }


def summarize_alerts(alerts):
    summary = {
        "total_alerts": len(alerts),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for alert in alerts:
        severity = alert["severity"].lower()
        if severity in summary:
            summary[severity] += 1

    return summary