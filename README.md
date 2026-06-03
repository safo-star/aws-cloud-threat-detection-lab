# AWS Cloud Threat Detection Lab

## Overview

AWS Cloud Threat Detection Lab is a Safo Security cloud security project that analyzes simulated AWS CloudTrail-style logs and detects suspicious cloud activity.

The goal of this project is to demonstrate cloud security monitoring, IAM risk detection, SOC analyst thinking, severity scoring, and business-risk explanation.

This lab detects common AWS security risks such as failed login bursts, root account usage, MFA being disabled, administrator permissions being attached, access key creation, public S3 bucket exposure, large S3 downloads, and CloudTrail logging being stopped.

---

## Business Problem

Businesses are increasingly using cloud platforms like AWS to store customer data, run applications, manage files, and operate internal systems.

If a cloud account is compromised, an attacker may:

- Log in without MFA
- Use the root account
- Disable MFA
- Add administrator permissions
- Create access keys for persistence
- Make S3 buckets public
- Download sensitive data
- Stop CloudTrail logging to hide activity

This project simulates how a security team could detect those behaviors from cloud logs.

---

## Features

- Failed AWS login burst detection
- Successful login without MFA detection
- Root account usage detection
- MFA disabled detection
- AdministratorAccess policy detection
- Access key creation detection
- Public S3 bucket exposure detection
- Large S3 data download detection
- CloudTrail logging stopped detection
- Risk scoring
- Severity labels
- Recommended remediation actions
- Streamlit dashboard
- JSON-style alert output

---

## Tech Stack

- Python
- Streamlit
- JSON
- Rule-based detection logic
- Simulated AWS CloudTrail-style logs

---

## Detection Logic

The lab analyzes simulated cloud logs and generates alerts when risky activity appears.

Example detections:

| Detection | Severity | Risk |
|---|---:|---:|
| CloudTrail Logging Stopped | Critical | 100/100 |
| Root Account Usage | Critical | 95/100 |
| S3 Bucket Made Public | Critical | 95/100 |
| MFA Disabled | Critical | 90/100 |
| Administrator Policy Attached | Critical | 90/100 |
| Large S3 Data Download | High | 85/100 |
| Access Key Created | High | 80/100 |
| Successful Login Without MFA | High | 75/100 |
| Failed Login Burst | Medium | 60/100 |

---

## Example Alert

```text
Alert: CloudTrail Logging Stopped
Severity: Critical
Risk Score: 100/100
User: alex-admin
Source IP: 203.0.113.55
Description: CloudTrail logging was stopped, reducing visibility into AWS account activity.
Recommendation: Re-enable CloudTrail immediately and investigate the user who stopped logging.