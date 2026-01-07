# Initial Access Detections

This folder contains **Microsoft Sentinel analytic rules and hunting queries** focused on detecting **initial access activity** — the point at which an attacker first gains a foothold in an environment.

Detections here are designed to identify early-stage compromise signals so incidents can be contained before lateral movement, persistence, or impact occurs.

---

## Scope & Objectives

The goals of the detections in this folder are to:

- Detect common and emerging **initial access techniques**
- Surface high-risk authentication and exposure events early
- Reduce attacker dwell time through early alerting
- Support both alert-based detection and proactive threat hunting

These rules primarily align to **MITRE ATT&CK – Initial Access (TA0001)**.

---

## Common Initial Access Techniques Covered

Detections in this folder may address:

- Phishing-based access (credential harvesting, token theft)
- Valid account abuse (brute force, password spray, MFA fatigue)
- Exploitation of public-facing applications
- Malicious file or link delivery
- OAuth and cloud app abuse
- Suspicious sign-ins from new or risky locations
- Unusual device or user behavior during first access
