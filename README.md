# Multi-Framework Regulatory Compliance & Gap Analysis Dashboard

## 🚀 Architectural Overview
This Technical GRC utility establishes an automated data schema cross-mapping organizational technical security controls to three critical security baselines: **NIST CSF v2.0**, **ISO/IEC 27001:2022**, and the **Dubai Electronic Security Center (DESC) ISR v3.0** standard. 

By mapping internal operational controls directly to disparate regulatory IDs, the engine enforces an architecture of **"Assess Once, Comply Many"** eliminating redundant assessment tracking and highlighting cross-framework gap dependencies instantly.

## 📊 Sample Posture JSON Output
```json
{
    "executive_readiness_summary": {
        "NIST_CSF_v2": "75.0% Ready (3/4 Controls)",
        "ISO_27001_2022": "75.0% Ready (3/4 Controls)",
        "DESC_ISR_v3": "75.0% Ready (3/4 Controls)"
    }
}
```

## 🎯 Key Features
* **Cross-Framework Control Mapping:** Directly translates single operational safeguards into explicit requirements across global and regional compliance baselines simultaneously.
* **Automated Posture Calculations:** Evaluates active audit evidence status to dynamically generate percentage-based compliance readiness metrics.
* **Localized Regulatory Alignment:** Pre-mapped to the **Dubai Electronic Security Center (DESC) ISR v3.0** standard for immediate regional audit readiness.

## ⚙️ How to Run & Test
To execute the compliance gap assessment engine and generate the structured JSON audit artifacts locally, run:

```powershell
git clone https://github.com/Saeidh5/compliance-dashboard.git
cd compliance-dashboard
python compliance_engine.py
```