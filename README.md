# 🛡️ Automated Multi-Framework Regulatory Compliance Auditor

An enterprise-grade Compliance-as-Code (CSPM) automation engine that ingests infrastructure configuration states, evaluates nested asset criteria thresholds, and dynamically maps control gaps across global and regional regulatory frameworks.

## 📊 Supported Framework Mappings
- **NIST CSF v2.0** (National Institute of Standards and Technology)
- **ISO/IEC 27001:2022** (Information Security Management)
- **Dubai DESC ISR v3.0** (Information Security Regulation)

## ⚡ Technical Capabilities
- **Advanced Schema Validation:** Evaluates deeply nested JSON configuration structures instead of arbitrary flat variables.
- **Array Token Scanning:** Loops through deployment arrays to dynamically verify the presence of approved security scanner binaries (`trivy`, `nessus`, etc.).
- **Privilege Escalation Auditing:** Traverses IAM role permission blocks to isolate dangerous wildcard (`*`) administration policies.
- **Automated DevSecOps Pipeline:** Built-in headless execution mode integrated via GitHub Actions to automatically run scans and generate compliance reports on code commits.
- **Interactive UI Dashboard:** Built-in Gradio web server for seamless, file-drop auditing interaction.

## 🚀 Getting Started

### 1. Installation & Environment Setup
Clone the repository and install the required dependencies:
```bash
git clone [https://github.com/Saeidh5/compliance-dashboard.git](https://github.com/Saeidh5/compliance-dashboard.git)
cd compliance-dashboard
pip install gradio
```
### 2. Launch the Web Interface
```bash
python compliance_engine.py
```
Open your browser and navigate to http://127.0.0.1:7860

### 3. Running an Automated Scan
- Triggers a headless scan execution using system_state.json.
- Validates security policies in the cloud environment.
- Outputs and caches a downloadable compliance artifact.

## 📄 Output Artifacts
The application automatically generates a standardized, machine-readable compliance_gap_analysis.json file upon each run. This structured data is optimized for ingestion into SIEM platforms or executive BI dashboards (e.g., PowerBI) for continuous compliance monitoring.