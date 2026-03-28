# 📁 /docs — PCI DSS Documentation Templates

This folder contains redacted templates for all documentation artifacts produced during the PCI DSS 4.0.1 ROC engagement. Replace placeholder text with your organization's details before use.

---

## 📄 Documents in this folder

| Document | PCI DSS Requirement | Description |
|---|---|---|
| `network-diagram.md` | 1.2.4, 12.5.1 | CDE network topology and segmentation diagram guidance |
| `data-flow-diagram.md` | 12.5.1 | Cardholder data flow from entry to exit |
| `risk-assessment.md` | 12.3.1 | Annual risk assessment template |
| `incident-response-plan.md` | 12.10.1 | IR plan covering detection, containment, recovery |
| `security-awareness-training.md` | 12.6.1 | Training program structure and completion tracking |
| `SOP_access-control.md` | 7.x, 8.x | Standard operating procedure for access provisioning |
| `SOP_log-review.md` | 10.4.1 | Daily log review procedure |
| `prompts/` | — | AI prompts (Claude/ChatGPT) for SOP and narrative generation |

---

## ⚠️ Usage Notes

- All documents use **synthetic/redacted data**
- Replace `[COMPANY]`, `[DATE]`, `[OWNER]` placeholders before use
- Store completed documents in a **private repo or secure document management system**
- Never commit real network diagrams, IP addresses, or system names to a public repo

---

## 🤖 AI Prompts (`/docs/prompts/`)

The `/prompts` folder contains Claude and ChatGPT prompt templates used to:
- Summarize raw log evidence into auditor-facing narratives
- Generate SOP first drafts from bullet-point process descriptions
- Produce gap memo language from the gap analysis report
- Standardize policy language across PCI DSS requirement domains

See `prompts/README.md` for usage instructions.
