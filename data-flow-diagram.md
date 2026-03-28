# 🔄 Cardholder Data Flow Diagram — PCI DSS 12.5.1

> **Status:** Redacted template — replace placeholders with your environment details.

---

## 📋 Document Control

| Field | Value |
|---|---|
| **Document Owner** | [OWNER] |
| **Last Reviewed** | [DATE] |
| **Next Review Due** | [DATE + 12 months] |
| **PCI DSS Requirement** | 12.5.1 |
| **Classification** | Confidential — Internal Use Only |

---

## 🗺️ Cardholder Data Flow

```
MERCHANT / CUSTOMER
        │
        │  Card data entered (PAN, expiry, CVV)
        ▼
┌───────────────────┐
│  Payment Form     │  ← Hosted fields / iFrame (CHD never hits merchant server)
│  (Web / Mobile)   │    or direct API submission
└────────┬──────────┘
         │  HTTPS / TLS 1.2+  (PCI DSS 4.2.1)
         ▼
┌───────────────────┐
│   API Gateway /   │  ← WAF enforced (PCI DSS 6.4.1)
│   Load Balancer   │    TLS termination
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Payment Service  │  ← Authorization logic
│  (App Server)     │    PAN used for auth only — never logged
└────────┬──────────┘
         │
         ├──────────────────────────────────┐
         │                                  │
         ▼                                  ▼
┌─────────────────┐               ┌──────────────────┐
│  Payment        │               │  Token Store     │
│  Processor/     │               │  (DB Server)     │
│  Acquirer       │               │  PAN → Token     │
│  (External)     │               │  (PCI DSS 3.5.1) │
└─────────────────┘               └──────────────────┘
         │
         ▼
  Authorization Response
  (Token + Auth code returned — no PAN)
         │
         ▼
┌───────────────────┐
│  Log / SIEM       │  ← Audit logs only (no PAN logged)
│  Server           │    PCI DSS 10.2.1, 10.3.1
└───────────────────┘
```

---

## 📍 CHD Locations Inventory

| Location | Data Elements Present | Encrypted | Tokenized | Notes |
|---|---|---|---|---|
| Payment Form (client-side) | PAN, Expiry, CVV | In transit (TLS) | No | CVV never stored |
| API Gateway | PAN (transit only) | TLS 1.2+ | No | Not persisted |
| App Server (memory) | PAN (auth only) | In memory | No | Cleared post-auth |
| Token Store (DB) | Token (no PAN) | At rest (AES-256) | Yes | PAN never stored |
| Payment Processor | PAN (external) | Per processor standards | Per processor | TPSP — AOC on file |
| Log Server | No PAN | N/A | N/A | Scrubbed before logging |
| Backups | Token only | Encrypted | Yes | No PAN in backups |

---

## 🔐 CHD Protection Controls Summary

| Control | Implementation | PCI DSS Req |
|---|---|---|
| TLS 1.2+ for all CHD in transit | Enforced at API gateway | 4.2.1 |
| PAN tokenization | [TOKEN VENDOR REDACTED] | 3.5.1 |
| CVV never stored | Application logic + log scrubbing | 3.3.1 |
| PAN masked in logs | Redact pipeline (`redact_patterns.txt`) | 3.5.1 |
| Encryption at rest | AES-256 on DB server | 3.5.1 |
| Access to CHD restricted | RBAC + MFA enforced | 7.2.1, 8.3.1 |

---

## ✅ Annual Data Flow Validation

| Field | Value |
|---|---|
| **Validated By** | [OWNER] |
| **Validation Date** | [DATE] |
| **Changes Since Last Review** | [None / Describe] |
| **Next Review Due** | [DATE + 12 months] |
