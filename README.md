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
- **Dynamic Playbook Generation:** Automatically outputs tailored, markdown-formatted technical remediation steps for any failed control.
- **Interactive UI Dashboard:** Built-in Gradio web server for seamless, file-drop auditing interaction.

## 🚀 Getting Started

### 1. Installation & Environment Setup
Clone the repository and install the required dependencies:
```bash
git clone https://github.com/Saeidh5/compliance-dashboard.git
cd compliance-dashboard
pip install gradio
```
### 2. Launch the Web Interface
```bash
python compliance_engine.py
```
Open your browser and navigate to http://127.0.0.1:7860

### 3. Running an Automated Scan
- Locate the mock file system_state.json provided in this repository.
- Drag and drop it into the Ingest Audit Configuration Evidence interface panel.
- Click Execute Deep Compliance Scan to generate real-time metrics, dynamic remediation playbooks, and the compliance report artifact.

## 📄 Output Artifacts
The application automatically generates a standardized, machine-readable compliance_gap_analysis.json file upon each run. This structured data is optimized for ingestion into SIEM platforms or executive BI dashboards (e.g., PowerBI) for continuous compliance monitoring.