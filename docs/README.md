# 🤖 AI Prompt Templates — PCI DSS Documentation

> These prompts were used with Claude and ChatGPT to accelerate SOP drafting,
> log summarization, and auditor-facing narrative generation during the PCI DSS 4.0.1 ROC.
> Copy the prompt, paste into your AI assistant, and fill in the bracketed variables.

---

## 📋 Prompt Index

| Prompt | Use Case | PCI DSS Req |
|---|---|---|
| [1] Evidence Summary Narrative](#1-evidence-summary-narrative) | Summarize raw log/evidence JSON for QSA | 10.2.1 |
| [2] Gap Memo Narrative](#2-gap-memo-narrative) | Executive summary of compliance gaps | 12.3.1 |
| [3] SOP First Draft](#3-sop-first-draft) | Generate SOP from bullet-point process | 7.x, 8.x, 10.x |
| [4] Policy Language Standardizer](#4-policy-language-standardizer) | Rewrite policy in auditor-friendly language | 12.1.1 |
| [5] Quarterly Change Summary](#5-quarterly-change-summary) | Summarize what changed since last quarter | 12.5.1 |
| [6] Risk Assessment Narrative](#6-risk-assessment-narrative) | Convert risk register to narrative prose | 12.3.1 |
| [7] Incident Response Tabletop Summary](#7-incident-response-tabletop-summary) | Document tabletop exercise findings | 12.10.1 |

---

## 1. Evidence Summary Narrative

**Use:** After running `export-logs.py`, paste the normalized JSON summary and use this prompt to produce a QSA-ready narrative.

```
You are a PCI DSS compliance analyst preparing evidence narratives for a QSA audit.

I will provide a JSON summary of evidence collected for PCI DSS control [CONTROL_ID — e.g. 8.1.1].

Write a 2–3 paragraph auditor-facing narrative that:
- Describes what was collected and from which systems
- Confirms the control requirement is met based on the evidence
- Notes any gaps or items requiring manual verification
- Uses formal, precise language suitable for a Report on Compliance (ROC)

Evidence JSON:
[PASTE NORMALIZED JSON HERE]
```

---

## 2. Gap Memo Narrative

**Use:** After running `gap-analysis.py`, paste the gap report and use this prompt to produce an executive gap memo.

```
You are a PCI DSS compliance consultant writing an executive gap memo for a fintech SaaS company.

Based on the following gap analysis results, write a concise executive memo (1 page max) that:
- States the current compliance posture (% controls with evidence)
- Lists the top 3–5 highest priority gaps with brief explanation
- Recommends immediate next steps for each gap
- Uses business-friendly language (not overly technical)
- Ends with a recommended timeline to close all gaps before the QSA assessment

Gap Analysis Results:
[PASTE GAP ANALYSIS MARKDOWN HERE]
```

---

## 3. SOP First Draft

**Use:** Turn a bullet-point process description into a full SOP document.

```
You are a PCI DSS compliance specialist writing standard operating procedures for a fintech SaaS company.

Write a complete SOP document for the following process. The SOP must include:
- Purpose statement
- Scope
- Step-by-step procedure table (Step | Action | Owner | Evidence)
- Escalation criteria
- Review frequency and attestation section
- Format it in Markdown with clear headings

Process description:
[DESCRIBE YOUR PROCESS IN BULLET POINTS HERE]

PCI DSS requirements this SOP covers: [LIST REQUIREMENTS e.g. 7.2.1, 8.3.1]
```

---

## 4. Policy Language Standardizer

**Use:** Rewrite an existing internal policy in PCI DSS-compliant, auditor-friendly language.

```
You are a PCI DSS QSA reviewing and rewriting information security policies.

Rewrite the following policy section so that it:
- Clearly states the requirement and who it applies to
- Uses "must" / "shall" language (not "should" or "may")
- References the specific PCI DSS 4.0.1 requirement it satisfies
- Is unambiguous and audit-ready
- Keeps it under 200 words

Original policy text:
[PASTE POLICY TEXT HERE]

PCI DSS requirement this covers: [REQUIREMENT ID]
```

---

## 5. Quarterly Change Summary

**Use:** Summarize changes to the CDE environment since the last review for scope validation.

```
You are a PCI DSS compliance analyst preparing a quarterly CDE scope change summary.

Based on the following list of changes made in the past quarter, write a structured summary that:
- Lists each change and its impact on PCI DSS scope (in scope / out of scope / no change)
- Flags any changes that may require a scope re-validation
- Notes any changes that require updated network or data flow diagrams
- Is suitable for review by a QSA

Changes this quarter:
[LIST CHANGES — e.g. new server added, firewall rule changed, vendor added]
```

---

## 6. Risk Assessment Narrative

**Use:** Convert a risk register table into narrative prose for the annual risk assessment document.

```
You are a PCI DSS compliance analyst writing the narrative section of an annual risk assessment.

Based on the following risk register, write a 3–4 paragraph narrative that:
- Summarizes the overall risk posture of the cardholder data environment
- Highlights the highest-risk items and their mitigations
- Confirms that residual risk is acceptable
- Is suitable for executive review and QSA submission

Risk Register:
[PASTE RISK REGISTER TABLE HERE]
```

---

## 7. Incident Response Tabletop Summary

**Use:** Document a tabletop exercise in a format suitable for QSA evidence.

```
You are a PCI DSS compliance analyst documenting a tabletop incident response exercise.

Based on the following notes from our tabletop exercise, write a structured summary that includes:
- Exercise date, participants, and scenario description
- Timeline of simulated actions taken
- Gaps or weaknesses identified during the exercise
- Remediation actions agreed upon
- Format suitable for QSA evidence submission (PCI DSS 12.10.1)

Tabletop notes:
[PASTE YOUR NOTES HERE]

Scenario: [e.g. Ransomware detected in CDE / Phishing leading to credential compromise]
Date: [DATE]
Participants: [ROLES — no names needed]
```

---

_These prompts work with Claude, ChatGPT (GPT-4+), and Gemini Advanced._
_Always review AI-generated output before submitting to a QSA._

