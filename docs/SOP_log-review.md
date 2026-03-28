# 📜 SOP: Daily Log Review — PCI DSS 10.4.1

---

## 📋 Document Control

| Field | Value |
|---|---|
| **SOP Owner** | [OWNER] |
| **Last Reviewed** | [DATE] |
| **Next Review Due** | [DATE + 12 months] |
| **PCI DSS Requirements** | 10.2.1, 10.3.1, 10.4.1, 10.5.1 |

---

## 🎯 Purpose

This SOP defines the daily log review process for all CDE systems to ensure audit log integrity, detect anomalies, and support timely incident response.

---

## 📡 Log Sources in Scope

| System | Log Type | Retention | Location |
|---|---|---|---|
| App Servers | Application + access logs | 12 months | [LOG SERVER / SIEM REDACTED] |
| DB Servers | Query logs, admin access | 12 months | [LOG SERVER / SIEM REDACTED] |
| Firewalls | Accept/deny traffic logs | 12 months | [LOG SERVER / SIEM REDACTED] |
| Entra ID / AD | Authentication, MFA events | 12 months | [LOG SERVER / SIEM REDACTED] |
| Intune / MDM | Device compliance events | 12 months | [LOG SERVER / SIEM REDACTED] |
| Log Server | Log integrity / forwarding | 12 months | Local + backup |

---

## 🔄 Daily Review Process

| Step | Action | Owner | Time |
|---|---|---|---|
| 1 | Log in to [SIEM / LOG PLATFORM REDACTED] | IT / Security Analyst | 09:00 daily |
| 2 | Review automated alert queue — acknowledge or escalate | IT / Security Analyst | 09:00–09:30 |
| 3 | Review failed authentication events (threshold: >5 in 10 min) | IT / Security Analyst | Daily |
| 4 | Review privileged account activity (admin logins, sudo, elevation) | IT / Security Analyst | Daily |
| 5 | Review after-hours CDE access events | IT / Security Analyst | Daily |
| 6 | Review firewall deny logs for unusual patterns | IT / Security Analyst | Daily |
| 7 | Confirm log integrity — no gaps or tampering detected | IT / Security Analyst | Daily |
| 8 | Document review completion in log review register | IT / Security Analyst | Daily |
| 9 | Escalate anomalies to IR Lead per Incident Response Plan | IT / Security Analyst | As needed |

---

## 🚨 Escalation Thresholds

| Event | Threshold | Action |
|---|---|---|
| Failed logins (single account) | > 5 in 10 minutes | Investigate + consider account lock |
| Failed logins (multiple accounts) | > 10 in 10 minutes | Escalate to IR Lead — possible brute force |
| Admin account login outside hours | Any | Investigate immediately |
| Log gap / missing logs | Any | Escalate to IR Lead — possible tampering |
| New admin account created | Any | Verify against change ticket |
| Firewall rule change | Any | Verify against change ticket |
| CDE outbound traffic to unknown IP | Any | Block + investigate |

---

## 📋 Log Review Register

| Date | Reviewer | Alerts Found | Anomalies | Escalated | Notes |
|---|---|---|---|---|---|
| [DATE] | [REVIEWER] | [#] | None | No | Routine |
| [DATE] | [REVIEWER] | [#] | Failed logins — [USER REDACTED] | No | Investigated — user locked out |
| [DATE] | [REVIEWER] | [#] | After-hours admin login | Yes | Escalated to IR Lead |

---

## 🔒 Log Integrity Controls (PCI DSS 10.3.1)

- Logs forwarded to centralized [SIEM / LOG SERVER] in real time
- Log server access restricted to security team only
- Log deletion or modification requires dual approval
- Log integrity verified daily via hash comparison / SIEM alerts
- Logs retained for 12 months minimum; 3 months immediately accessible

---

## ✅ SOP Review Attestation

| Field | Value |
|---|---|
| **Reviewed By** | [OWNER] |
| **Review Date** | [DATE] |
| **Next Review** | [DATE + 12 months] |
