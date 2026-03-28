# 🔐 SOP: Access Control & User Provisioning — PCI DSS 7.x / 8.x

---

## 📋 Document Control

| Field | Value |
|---|---|
| **SOP Owner** | [OWNER] |
| **Last Reviewed** | [DATE] |
| **Next Review Due** | [DATE + 12 months] |
| **PCI DSS Requirements** | 7.1, 7.2, 7.3, 8.1, 8.2, 8.3, 8.6 |

---

## 🎯 Purpose

This SOP defines the process for provisioning, modifying, and revoking access to CDE systems and cardholder data, ensuring least privilege and need-to-know principles are enforced at all times.

---

## 👤 User Provisioning (New Access)

| Step | Action | Owner | Evidence |
|---|---|---|---|
| 1 | Manager submits access request via [TICKETING SYSTEM] | Hiring Manager | Ticket record |
| 2 | IT validates business justification for CDE access | IT / Compliance | Approval record |
| 3 | Account created with minimum required permissions (RBAC) | IT Admin | Account creation log |
| 4 | MFA enrolled before first login | IT Admin | MFA enrollment record |
| 5 | User completes security awareness training | HR / IT | Training completion record |
| 6 | Access confirmed and ticket closed | IT Admin | Ticket closure |

---

## 🔄 Access Modification

| Step | Action | Owner | Evidence |
|---|---|---|---|
| 1 | Manager submits change request | Manager | Ticket record |
| 2 | IT validates new role justification | IT / Compliance | Approval record |
| 3 | Permissions updated in [IAM SYSTEM / Entra ID] | IT Admin | Change log |
| 4 | Previous excess permissions removed | IT Admin | Permission diff |

---

## ❌ Access Revocation (Termination / Role Change)

| Step | Action | SLA | Owner | Evidence |
|---|---|---|---|---|
| 1 | HR notifies IT of termination or role change | Same day | HR | HR notification |
| 2 | Account disabled in Entra ID / Active Directory | Within 1 hour (termination) | IT Admin | Disable log |
| 3 | MFA tokens revoked | Within 1 hour | IT Admin | MFA revocation log |
| 4 | All active sessions terminated | Within 1 hour | IT Admin | Session termination log |
| 5 | VPN / remote access revoked | Within 1 hour | IT Admin | VPN access log |
| 6 | Privileged accounts reviewed for orphaned access | Within 24 hours | IT / Compliance | Access review record |

---

## 🔁 Periodic Access Reviews

Per PCI DSS 7.3.1, all CDE user access is reviewed at minimum every **6 months** for standard users and **3 months** for privileged/admin accounts.

| Review Type | Frequency | Owner | Evidence |
|---|---|---|---|
| Standard user CDE access | Every 6 months | IT / Compliance | Access review report |
| Privileged / admin accounts | Every 3 months | IT / Compliance | Privileged access review report |
| Service / system accounts | Every 6 months | IT | Service account inventory |
| Third-party / vendor accounts | Every 6 months | IT / Compliance | TPSP access review |

---

## 🔑 Password & MFA Requirements (PCI DSS 8.3.6)

| Requirement | Standard | Enforcement |
|---|---|---|
| Minimum password length | 12 characters | Entra ID / GPO |
| Complexity | Upper, lower, number, symbol | Entra ID / GPO |
| Password history | Last 4 passwords | Entra ID / GPO |
| MFA for CDE access | Required — all users | Conditional Access Policy |
| MFA for remote access | Required | VPN / Conditional Access |
| Admin account MFA | Required | Privileged Identity Management |

---

## ✅ SOP Review Attestation

| Field | Value |
|---|---|
| **Reviewed By** | [OWNER] |
| **Review Date** | [DATE] |
| **Next Review** | [DATE + 12 months] |
