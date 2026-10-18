# ThreatTrack — Product Requirements Document (PRD)

| Metadata | Details |
| :--- | :--- |
| **Product Name** | ThreatTrack: Contextual Vulnerability Triage & SLA Platform |
| **Document Version** | 1.0.0 (Enterprise Baseline) |
| **Status** | Approved & Implemented |
| **Target Launch** | Q4 2026 |
| **Author** | Principal Cybersecurity & Product Engineer |
| **Audience** | SecOps Teams, Platform Engineering, CISO Executive Staff, GRC Auditors |

---

## 1. Executive Summary & Problem Statement

### 1.1 The Industry Dilemma: Vulnerability Fatigue & Context Blindness
Modern security operations are inundated with thousands of Common Vulnerabilities and Exposures (CVEs) emitted weekly by vulnerability scanners (e.g., Tenable, Qualys, Snyk, Wiz). Security teams face two systemic breakdowns:

1. **Context Blindness:** Scanners score vulnerabilities strictly using base Common Vulnerability Scoring System (CVSS) metrics. Under pure CVSS, a `CVSS 9.8` vulnerability on an isolated internal development sandbox triggers the identical critical escalation as a `CVSS 9.8` on a customer-facing production payment gateway. This lack of business and environmental context squanders scarce engineering cycles on low-exposure targets while critical crown-jewel assets remain exposed.
2. **SLA Governance Blindspots:** Engineering and SecOps teams lack a single source of truth for tracking remediation aging against contractual and compliance Service Level Agreements (SLAs). Critical vulnerabilities silently slip past 7-day or 30-day mandates, resulting in SOC 2 / ISO 27001 audit findings and elevated dwell time for threat actors.

### 1.2 The ThreatTrack Solution
ThreatTrack introduces **Asset-Contextual Prioritization** and **Automated SLA Lifecycle Governance**. By blending raw vulnerability metrics with environment criticality weights ($\text{Risk Score} = \text{CVSS} \times \text{Asset Weight}$), ThreatTrack mathematically ranks vulnerabilities by true organizational risk and enforces unambiguous remediation countdowns.

---

## 2. Target Personas

### Persona 1: Alex Chen — Senior SecOps Engineer / Vulnerability Analyst
* **Role & Mandate:** Frontline triage, patching coordination with dev teams, incident containment.
* **Pain Points:**
  * Overwhelmed by raw scanner exports with 500+ "critical" alerts.
  * Friction with development teams who push back on patching non-production or non-exploitable boxes.
  * Inability to quickly generate executive-ready triage briefs during zero-day disclosure storms.
* **Goals in ThreatTrack:**
  * Instantly filter and rank vulnerabilities by contextual business impact.
  * Acknowledge exceptions, update triage states, and inspect patch availability in one console.
  * Download 1-click executive PDF briefs for emergency patch reviews.

### Persona 2: Sarah Jenkins — Chief Information Security Officer (CISO)
* **Role & Mandate:** Executive cybersecurity governance, risk posture management, audit compliance.
* **Pain Points:**
  * Inability to quantify enterprise exposure to the Board of Directors and Audit Committee.
  * Lack of visibility into Mean Time to Remediation (MTTR) trends and SLA breach liabilities.
  * Difficulty demonstrating risk reduction trajectory across quarterly audits.
* **Goals in ThreatTrack:**
  * Real-time dashboard visibility into enterprise SLA compliance rates (target $\ge 95\%$).
  * Clear environmental breakdowns showing production vs staging risk burdens.
  * Standardized executive reporting collateral to present to risk committees.

---

## 3. Product Vision & Principles

* **Context is King:** A vulnerability's severity is a function of its technical exploitability *multiplied* by where it lives.
* **Zero Operational Latency:** Triage workflows must be lightweight, interactive, and actionable in seconds.
* **Deterministic Governance:** SLA rules and risk scoring must be fully transparent, repeatable, and audit-verifiable without black-box AI hallucinations.
* **Actionable Output:** Every flagged node must have an owner, an SLA window, and a remediation playbook.

---

## 4. Mathematical & Policy Architecture

### 4.1 Contextual Risk Formula
$$\text{Contextual Risk Score} = \text{CVSS v3 Base Score} \times \text{Asset Criticality Weight}$$

| Environment | Asset Criticality Weight | Description / Scope |
| :--- | :---: | :--- |
| **Production** | **1.5** | Customer-facing services, payment gateways, primary datastores, auth providers. |
| **Staging** | **1.0** | Pre-production validation environments, mirror clusters, QA testbeds. |
| **Internal** | **0.5** | Developer sandboxes, internal documentation wikis, isolated build runners. |

#### Operational Risk Bands
* **Extreme Risk ($\ge 12.0$):** Immediate 24-hour escalation, emergency change-freeze exemption.
* **High Risk ($8.0 - 11.9$):** Prioritized sprint backlog, immediate staging validation.
* **Moderate Risk ($4.0 - 7.9$):** Standard patch management cycle.
* **Low Risk ($< 4.0$):** Routine scheduled maintenance or accepted residual risk.

### 4.2 SLA Governance Thresholds
Remediation deadlines are calculated strictly from the date of discovery:

| Severity Tier | CVSS Score Range | Mandated SLA Target | Escalation Threshold ("At Risk") |
| :--- | :---: | :---: | :--- |
| **Critical** | $9.0 - 10.0$ | **7 Calendar Days** | $\le 2$ days remaining or $\ge 75\%$ elapsed |
| **High** | $7.0 - 8.9$ | **30 Calendar Days** | $\le 7$ days remaining or $\ge 75\%$ elapsed |
| **Medium** | $4.0 - 6.9$ | **60 Calendar Days** | $\le 14$ days remaining |
| **Low** | $0.1 - 3.9$ | **90 Calendar Days** | $\le 15$ days remaining |

---

## 5. Core Product Epics & Functional Requirements

### Epic 1: Asset-Centric Data Ingestion & Enrichment
* **REQ-1.1:** Support catalog ingestion of infrastructure assets mapped to known CVE identifiers.
* **REQ-1.2:** Maintain deterministic seeding for consistent demonstrations and repeatable automated testing.
* **REQ-1.3:** Dynamically calculate asset weights, contextual risk scores, and SLA health indicators.

### Epic 2: CISO Executive Analytics & Governance Dashboard
* **REQ-2.1:** High-visibility KPI ribbons showing Fleet Backlog, Critical/High counts, Active SLA Breaches, Global Compliance %, and MTTR.
* **REQ-2.2:** Environment risk distribution visualization (Production vs Staging vs Internal).
* **REQ-2.3:** SLA status breakdown visualizing Breached vs At-Risk vs In-SLA assets.
* **REQ-2.4:** Vulnerability aging scatterplot mapping days open against contextual risk.

### Epic 3: SecOps Interactive Triage Console
* **REQ-3.1:** Fast multi-attribute filtering by Environment, Severity, SLA Status, and free-text search.
* **REQ-3.2:** Asset Inspector detail drawer displaying IP address, owning engineering team, affected component, and exploit availability.
* **REQ-3.3:** Quick-action status transitions (`Mark In-Progress`, `Mark Resolved`, `Approve Exception`) that dynamically recalculate compliance metrics.

### Epic 4: Top 5 High-Risk Queue & What-If Simulator
* **REQ-4.1:** Real-time ranking of top 5 highest contextual risk nodes with explicit remediation directives.
* **REQ-4.2:** Interactive scenario simulator allowing engineers to test CVSS changes, environmental migrations, and aging against SLA outcomes.

### Epic 5: Executive PDF Briefing Exporter
* **REQ-5.1:** One-click generation of audit-ready, 1-page PDF briefings containing KPI summaries, environmental breakdowns, top 5 prioritized nodes, and SecOps directives.
* **REQ-5.2:** In-browser download delivery without external network dependencies.

---

## 6. Non-Functional Requirements (NFRs)

* **Performance:** Sub-second filter latency across $10,000+$ vulnerability nodes.
* **Air-Gap Capability:** Capable of running completely on-premises or air-gapped without external SaaS callbacks.
* **Security & Confidentiality:** Strict redaction and classification headers (`CONFIDENTIAL - SEC ENG ONLY`) on all exported artifacts.
* **Reliability:** 100% deterministic calculation reproducibility across all client sessions.

---

## 7. Success Metrics & Key Performance Indicators (KPIs)

* **MTTR Compression:** Reduce Mean Time to Remediation for Critical Production CVEs by $40\%$ within 90 days of deployment.
* **SLA Breach Mitigation:** Maintain $>95\%$ enterprise SLA compliance rate across production workloads.
* **Triage Efficiency:** Reduce SecOps manual triage overhead from 12 hours/week to $<2$ hours/week.
