# PCI DSS 4.0.1 Certification Automation

> Scripts, workflows, and documentation patterns to automate **PCI DSS 4.0.1 evidence collection**, **control verification**, and **audit preparation** for fintech teams. Designed to be adapted to SOC 2 and ISO 27001 with a control crosswalk.

## 🔍 Overview
This repo shows how I reduced audit prep time by ~60% through:
- Automated evidence exports (PowerShell + Python)
- Normalized JSON/CSV outputs with metadata (system, timestamp, control id)
- Evidence-to-control mapping and a PCI→SOC 2 crosswalk
- AI-assisted summarization (ChatGPT) and rewriting (Claude) for SOPs and auditor-facing docs

> **Note on data:** All examples are **redacted** and use synthetic data. Replace placeholders with your environment variables and scrub sensitive info before sharing.

## 🏗️ Architecture
```
/scripts/            # PowerShell & Python collectors
  collect-evidence.ps1
  export-logs.py
  generate-report.py
/crosswalk/          # PCI <-> SOC 2 mapping CSV/JSON
/docs/               # SOPs, runbooks, screenshots (redacted)
/examples/           # Sample evidence + rendered reports
```
- **PowerShell** for Windows/Entra/Intune evidence
- **Python** for log parsing (JSON/CSV), report generation (Markdown/PDF)
- **OpenAI/Anthropic** prompts to summarize logs and standardize narratives

## ⚙️ Key Features
- **Evidence collectors** for common controls (e.g., 8.x, 10.x, 12.x)
- **Normalization pipeline**: raw → JSON → CSV → Markdown report
- **Audit-ready packets**: zipped bundles with hash manifest
- **Control crosswalk** between PCI and SOC 2 (Common Criteria)

## 🚀 Quick Start
```bash
# 1) Create a Python virtual environment
python -m venv .venv && source .venv/bin/activate

# 2) Install requirements
pip install -r requirements.txt

# 3) Run a targeted PCI control evidence grab
pwsh ./scripts/collect-evidence.ps1 -Control "8.1.1" -Export json -OutDir ./examples/8.1.1

# 4) Normalize logs and build a mini report
python ./scripts/export-logs.py --input ./examples/8.1.1 --output ./examples/8.1.1/normalized.json
python ./scripts/generate-report.py --control 8.1.1 --input ./examples/8.1.1 --out ./examples/8.1.1/REPORT_8.1.1.md
```

## 📄 Example Command
```powershell
.\scripts\collect-evidence.ps1 -Control "10.2.1" -Systems "Windows,Ubuntu,Firewalls" -Export json -OutDir .\examples.2.1
```

## 📈 Results (from a production fintech environment)
- ~60% reduction in audit preparation time
- Fewer manual errors and re-requests from the auditor
- Repeatable, documented runs w/ hash-verified artifacts

## 🔗 PCI→SOC 2 Crosswalk
- `crosswalk/pci_to_soc2.csv` maps sampled PCI requirements to SOC 2 CCs.
- Use `generate-report.py --framework soc2` to emit SOC 2-aligned evidence summaries.

## 🔐 Security & Redaction Notes
- Never commit raw log data, keys, or customer PII.
- Use `redact_patterns.txt` with `export-logs.py` to scrub hostnames, emails, public IPs.
- Store real evidence in a private repo or secure bucket with retention policy.

## 📚 Documentation
- `/docs/SOP_*` provide runbooks and narrative templates for controls.
- AI prompts in `/docs/prompts` standardize summaries (“What changed since last quarter?”).

## 🛣️ Roadmap
- [ ] Add Linux CIS module for 8.x & 10.x checks
- [ ] Add Juniper/Cisco config scrapers
- [ ] Add HTML + PDF report outputs
- [ ] Add ISO 27001 Annex A mapping

## 🧠 Skills & Tools
`PowerShell` `Python` `PCI DSS 4.0.1` `SOC 2` `Evidence Automation` `ChatGPT` `Claude`

## 📝 License
MIT — see `LICENSE`.

---

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Last commit](https://img.shields.io/github/last-commit/suresh-1001/pci-dss-certification-automation)


## Artifacts
- `/docs/` step-by-step with screenshots
- `/scripts/` repeatable automation
- `/dashboards/` sample JSON/PBIX (if relevant)
- `/templates/` redacted policies/SOPs

---
**Contact**  
- Email: **suresh@echand.com**  
- LinkedIn: **linkedin.com/in/sureshchand01**
