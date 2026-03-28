# ⚠️ Annual Risk Assessment — PCI DSS 12.3.1

---

## 📋 Document Control

| Field | Value |
|---|---|
| **Document Owner** | [OWNER] |
| **Assessment Date** | [DATE] |
| **Next Assessment Due** | [DATE + 12 months] |
| **PCI DSS Requirement** | 12.3.1 |
| **Classification** | Confidential |

---

## 🎯 Scope

This risk assessment covers all systems, processes, and personnel within the Cardholder Data Environment (CDE) as defined in the Network Diagram and Data Flow Diagram. It identifies threats to the confidentiality, integrity, and availability of cardholder data.

---

## 🔍 Risk Register

| Risk ID | Threat | Asset Affected | Likelihood (1-5) | Impact (1-5) | Risk Score | Status | Mitigation |
|---|---|---|---|---|---|---|---|
| R-001 | Unauthorized access to CDE | App / DB Servers | 3 | 5 | 15 | Mitigated | MFA enforced (8.3.1), RBAC (7.2.1) |
| R-002 | Phishing / credential compromise | All users | 4 | 4 | 16 | Mitigated | Security awareness training (12.6.1) |
| R-003 | Unpatched vulnerabilities | All in-scope systems | 3 | 5 | 15 | Mitigated | Quarterly vulnerability scans (11.3.1) |
| R-004 | Insider threat / privilege abuse | Admin accounts | 2 | 5 | 10 | Mitigated | Privileged access review (7.3.1), logging (10.2.1) |
| R-005 | Third-party / TPSP breach | Payment processor | 2 | 5 | 10 | Mitigated | AOC on file, contract review (12.8.1) |
| R-006 | Ransomware / malware | All systems | 3 | 5 | 15 | Mitigated | AV deployed (5.2.1), backups tested |
| R-007 | Data exfiltration via network | CDE network | 2 | 5 | 10 | Mitigated | IDS/IPS (11.5.1), egress filtering (1.3.2) |
| R-008 | Physical unauthorized access | Server room / CDE | 2 | 4 | 8 | Mitigated | Badge access + CCTV (9.1.1) |
| R-009 | Misconfigured firewall rule | Network perimeter | 2 | 5 | 10 | Mitigated | Quarterly firewall review (1.2.1) |
| R-010 | Log tampering / deletion | Log servers | 1 | 5 | 5 | Mitigated | Log integrity controls (10.3.1) |

**Risk Score = Likelihood × Impact (max 25)**
- 1–5: Low | 6–12: Medium | 13–19: High | 20–25: Critical

---

## 📈 Risk Summary

| Level | Count |
|---|---|
| Critical (20–25) | 0 |
| High (13–19) | 3 |
| Medium (6–12) | 5 |
| Low (1–5) | 2 |

---

## ✅ Attestation

| Field | Value |
|---|---|
| **Completed By** | [OWNER] |
| **Review Date** | [DATE] |
| **Approved By** | [EXECUTIVE SPONSOR] |
| **Next Assessment** | [DATE + 12 months] |
