# ThreatTrack Implementation Plan

## 1. Directory Structure
```text
threattrack/
├── app.py                     # Streamlit Main Dashboard Application
├── utils/
│   ├── data_loader.py        # Generates/loads mock assets & CVE data
│   └── engine.py             # Contextual Risk & SLA evaluation engine
├── product-docs/
│   ├── PRD.md                # Product Requirements Document
│   ├── RICE.md               # Prioritization Framework Matrix
│   └── DATASHEET.md          # 1-Page Product Collateral
└── requirements.txt          # App dependencies (streamlit, pandas, fpdf)
```

## 2. Technical Requirements & Architecture
* **Data Ingestion:** Generate a localized static seed catalog of 100 mock assets (`Production`, `Staging`, `Internal`) mapped against random CVEs (CVSS v3 scores ranging 1.0 - 10.0).
* **Risk Engine Calculations:** 
  \[\text{Risk Score} = \text{CVSS Score} \times \text{Asset Weight}\]
  * Weights: `Production` = 1.5, `Staging` = 1.0, `Internal` = 0.5.
* **SLA Target Rules:** Flag overdue items based on remediation timeframes:
  * Critical (CVSS 9.0+): 7 days
  * High (CVSS 7.0-8.9): 30 days
* **PDF Exporter:** Implement a simple one-click PDF compilation using `fpdf` or `reportlab` summarizing MTTR, total counts by severity, and Top 5 high-risk nodes.

## 3. Product Management Requirements
* **PRD.md:** Populate with Problem Statement, SecOps vs CISO user personas, and core Epics.
* **RICE.md:** Construct a Markdown table mapping Reach, Impact, Confidence, Effort for core features.
* **DATASHEET.md:** Product specs, key capabilities, and a brief customer onboarding FAQ.