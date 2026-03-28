# 🚨 Incident Response Plan — PCI DSS 12.10.1

---

## 📋 Document Control

| Field | Value |
|---|---|
| **Document Owner** | [OWNER] |
| **Last Reviewed** | [DATE] |
| **Next Review Due** | [DATE + 12 months] |
| **PCI DSS Requirement** | 12.10.1 |
| **Classification** | Confidential |

---

## 👥 Incident Response Team

| Role | Responsible Party | Contact |
|---|---|---|
| IR Lead | [OWNER / Director of IT] | [REDACTED] |
| Security Analyst | [NAME] | [REDACTED] |
| Legal / Compliance | [NAME] | [REDACTED] |
| Executive Sponsor | [NAME] | [REDACTED] |
| External IR Retainer | [VENDOR REDACTED] | [REDACTED] |
| PCI Forensic Investigator (PFI) | [PFI VENDOR REDACTED] | [REDACTED] |

---

## 🔄 Incident Response Phases

### Phase 1 — Preparation
- IR plan reviewed and approved annually
- IR team roles and contacts documented and communicated
- Tabletop exercise conducted annually
- Forensic tools and evidence collection procedures in place
- Contact list for card brands (Visa, Mastercard) and acquiring bank maintained

### Phase 2 — Detection & Identification
- Monitor SIEM / log server alerts (PCI DSS 10.4.1)
- Monitor IDS/IPS alerts (PCI DSS 11.5.1)
- Classify incident severity:

| Severity | Definition | Response SLA |
|---|---|---|
| P1 — Critical | Confirmed CHD breach or active exfiltration | Immediate — 1 hour |
| P2 — High | Suspected CHD exposure or system compromise | 4 hours |
| P3 — Medium | Policy violation, failed access attempts | 24 hours |
| P4 — Low | Anomalous activity, no confirmed impact | 72 hours |

### Phase 3 — Containment
- Isolate affected systems from CDE network
- Preserve forensic evidence (do not wipe systems)
- Disable compromised accounts
- Block malicious IPs at firewall
- Notify IR Lead and Legal immediately for P1/P2

### Phase 4 — Eradication
- Identify and remove malware / unauthorized access
- Patch exploited vulnerability
- Reset all potentially compromised credentials
- Conduct root cause analysis

### Phase 5 — Recovery
- Restore systems from clean, verified backups
- Confirm integrity of restored systems
- Re-enable services in controlled sequence
- Monitor closely for 72 hours post-recovery

### Phase 6 — Post-Incident Review
- Conduct post-mortem within 5 business days
- Document timeline, root cause, and lessons learned
- Update IR plan if gaps identified
- Report to card brands if CHD confirmed compromised (per brand requirements)

---

## 📞 Breach Notification Requirements

| Party | Trigger | Timeline |
|---|---|---|
| Acquiring Bank | Any confirmed CHD breach | Immediately |
| Visa / Mastercard | Confirmed or suspected CHD breach | Per card brand rules |
| Affected Merchants | CHD exposed via platform | Per contractual SLA |
| Regulatory Bodies | Per applicable law (GDPR, CCPA, etc.) | Per jurisdiction |

---

## 🧪 Tabletop Exercise Log

| Date | Scenario | Participants | Findings | Actions Taken |
|---|---|---|---|---|
| [DATE] | Ransomware in CDE | [TEAM LIST] | [FINDINGS] | [ACTIONS] |
| [DATE] | Phishing leading to credential compromise | [TEAM LIST] | [FINDINGS] | [ACTIONS] |

---

## ✅ Annual Review Attestation

| Field | Value |
|---|---|
| **Reviewed By** | [OWNER] |
| **Review Date** | [DATE] |
| **Tabletop Conducted** | Yes / No |
| **Next Review** | [DATE + 12 months] |
