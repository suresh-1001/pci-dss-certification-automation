# 🌐 Network Diagram & CDE Scope — PCI DSS 1.2.4 / 12.5.1

> **Status:** Redacted template — replace placeholders with your environment details.
> Store the completed version in a private repo or secure document system.

---

## 📋 Document Control

| Field | Value |
|---|---|
| **Document Owner** | [OWNER — e.g. Director of IT & Compliance] |
| **Last Reviewed** | [DATE] |
| **Next Review Due** | [DATE + 12 months] |
| **PCI DSS Requirement** | 1.2.4, 12.5.1 |
| **Classification** | Confidential — Internal Use Only |

---

## 🏗️ CDE Network Topology

```
┌─────────────────────────────────────────────────────────┐
│                     INTERNET                            │
└────────────────────────┬────────────────────────────────┘
                         │
                ┌────────▼────────┐
                │   FIREWALL/WAF  │  ← [VENDOR/MODEL REDACTED]
                │  (Perimeter)    │    Rules: PCI DSS 1.3.1
                └────────┬────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
   ┌──────▼──────┐ ┌─────▼──────┐ ┌───▼──────────┐
   │   DMZ Zone  │ │  CDE Zone  │ │  Corp Network│
   │  (Web/API)  │ │ (In Scope) │ │ (Out of Scope│
   │             │ │            │ │  if segmented)
   └─────────────┘ └─────┬──────┘ └──────────────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
       ┌──────▼──┐ ┌─────▼───┐ ┌───▼──────┐
       │  App    │ │  DB     │ │  Log     │
       │ Servers │ │ Servers │ │ Servers  │
       │ [REDACT]│ │ [REDACT]│ │ [REDACT] │
       └─────────┘ └─────────┘ └──────────┘
```

---

## 🔒 CDE Boundary Definition

| Zone | In CDE Scope | Reason |
|---|---|---|
| Web / API Layer (DMZ) | ✅ Yes | Transmits CHD to payment processor |
| Application Servers | ✅ Yes | Process payment transactions |
| Database Servers | ✅ Yes | Store tokenized transaction records |
| Log / SIEM Servers | ✅ Yes | Receive CDE audit logs |
| Corporate Network | ⚠️ Conditional | In scope if not fully segmented from CDE |
| HR / Finance Systems | ❌ No | Segmented; no CHD access |
| Developer Workstations | ❌ No | No production CDE access |

---

## 🔐 Network Segmentation Controls

| Control | Implementation | PCI DSS Req |
|---|---|---|
| Firewall between CDE and DMZ | [VENDOR/MODEL REDACTED] | 1.3.1 |
| Firewall between CDE and Corp | [VENDOR/MODEL REDACTED] | 1.3.2 |
| No direct internet access from CDE | Verified via ruleset review | 1.3.1 |
| IDS/IPS on CDE perimeter | [VENDOR REDACTED] | 11.5.1 |
| WAF on public-facing applications | [VENDOR REDACTED] | 6.4.1 |

---

## 📡 In-Scope System Inventory

| System | Role | IP (Redacted) | OS | Notes |
|---|---|---|---|---|
| [APP-01] | Application server | 10.x.x.x | Windows Server 2022 | Payment processing |
| [APP-02] | Application server | 10.x.x.x | Windows Server 2022 | Failover |
| [DB-01] | Database server | 10.x.x.x | Linux/Ubuntu 22.04 | Tokenized storage |
| [LOG-01] | Log aggregator | 10.x.x.x | Linux/Ubuntu 22.04 | SIEM forwarding |
| [FW-01] | Perimeter firewall | [REDACTED] | [VENDOR OS] | CDE boundary |

---

## ✅ Annual Scope Validation Attestation

> Per PCI DSS 12.5.1, CDE scope must be confirmed at least once every 12 months and after significant changes.

| Field | Value |
|---|---|
| **Validated By** | [OWNER] |
| **Validation Date** | [DATE] |
| **Method** | Scope validator script + manual network review |
| **Changes Since Last Review** | [None / Describe changes] |
| **Next Validation Due** | [DATE + 12 months] |

---

_Store completed diagram in private repo or secure document management system._
_Never commit real IP addresses or system hostnames to a public repository._
