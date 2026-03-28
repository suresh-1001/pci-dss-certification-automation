# 📋 Case Study 001: PCI DSS 4.0.1 Full ROC — Fintech SaaS Payment Processor

---

## 🏢 Context

A fintech SaaS platform processing payments on behalf of merchants faced its first **full PCI DSS 4.0.1 Report on Compliance (ROC)** assessment. The company had grown rapidly and inherited a patchwork of manual compliance processes — evidence was collected ad hoc, stored inconsistently, and required weeks of back-and-forth with the QSA (Qualified Security Assessor).

**Who was impacted:**
- Engineering and IT teams spending weeks manually pulling logs and screenshots
- The QSA requesting re-submissions due to missing metadata and inconsistent formatting
- Leadership facing audit timeline risk and potential merchant contract penalties for delayed certification

**Scope:**
- Windows Servers (on-prem and cloud-joined)
- Entra ID / Azure AD (identity, MFA, conditional access)
- Intune / MDM (device compliance policies)
- Linux / Ubuntu (application and log servers)
- Firewalls / Network devices (segmentation, rule reviews)

---

## 🎯 Objective

Design and execute a repeatable, automated evidence collection and reporting pipeline that could deliver a clean, complete PCI DSS 4.0.1 ROC evidence package — on time, with zero re-requests from the QSA.

---

## 🔧 Approach

1. **Mapped all 12 PCI DSS requirement domains** to specific evidence types per system (Windows, Linux, Entra ID, Intune, Firewalls)
2. **Built PowerShell collectors** (`collect-evidence.ps1`) targeting controls 8.x (access), 10.x (logging), and 12.x (policies) across all in-scope systems
3. **Built Python normalizers** (`export-logs.py`) to standardize raw outputs into JSON/CSV with required metadata fields: `control_id`, `system`, `timestamp`, `collector_version`
4. **Generated Markdown reports** per control (`generate-report.py`) formatted for direct handoff to the QSA
5. **Packaged evidence bundles** as zipped artifacts with SHA hash manifests for integrity verification
6. **Applied AI assistance** (Claude + ChatGPT) to draft and standardize SOP narratives, policy descriptions, and auditor-facing summaries across requirements
7. **Built a PCI DSS → SOC 2 crosswalk** (`crosswalk/pci_to_soc2.csv`) to simultaneously produce SOC 2 CC-aligned summaries from the same evidence run

---

## 📈 Results

| Metric | Before Automation | After Automation |
|---|---|---|
| Audit preparation time | ~5 weeks | ~2 weeks |
| QSA re-requests | Multiple rounds | Zero |
| Evidence consistency | Ad hoc, varied formats | Normalized JSON/CSV + Markdown |
| Artifact integrity | Unverified | SHA hash-verified bundles |
| Framework coverage | PCI DSS only | PCI DSS + SOC 2 crosswalk |
| Team hours saved per audit cycle | — | ~60% reduction |

> ✅ **Outcome:** Full PCI DSS 4.0.1 ROC completed successfully. Clean evidence package delivered to QSA with no re-requests. Pipeline is now reusable for annual recertification.

---

## 📦 Artifacts

- **Scripts:** [`./scripts/`](../../scripts/) — PowerShell & Python collectors and report generators
- **Crosswalk:** [`./crosswalk/`](../../crosswalk/) — PCI DSS → SOC 2 control mapping CSV
- **Docs:** [`./docs/`](../../docs/) — SOPs, runbooks, AI summarization prompts
- **Playbook:** [`./Portfolio-Playbook/`](../../Portfolio-Playbook/) — Capability overview and patterns

> ⚠️ All examples use **synthetic/redacted data**. No real merchant, customer, or system data is present in this repo.

---

## 🔮 What I'd Do Next

- **Add Linux CIS benchmark module** for automated hardening evidence on Ubuntu servers (controls 8.x & 10.x)
- **Add Juniper/Cisco config scrapers** for automated firewall rule review evidence (control 1.x)
- **Add GitHub Actions workflow** for scheduled quarterly evidence runs with automated diff reports
- **Extend crosswalk to ISO 27001 Annex A** for triple-framework coverage from a single evidence run
- **Build an HTML/PDF dashboard** for executive-level compliance status reporting

---

## 🧠 Skills Demonstrated

`PCI DSS 4.0.1` `SOC 2` `Full ROC` `Evidence Automation` `PowerShell` `Python` `Entra ID` `Intune` `Linux` `Firewall Review` `AI Prompt Engineering` `Claude` `ChatGPT` `GRC` `Audit Readiness`
