import json
import gradio as gr
from datetime import datetime

COMPLIANCE_DATABASE = {
    "CONTROL-01": {
        "title": "IAM Privileged Access Controls",
        "mappings": {"NIST": "PR.AA-P1", "ISO": "A.5.15", "DESC_ISR": "Domain 6"},
        "remediation": "🚨 FIX ACTION: Audit your configuration file. Ensure 'root_user' has 'mfa_enabled': true, and remove any wildcard ('*') administrative privileges from standard user roles."
    },
    "CONTROL-02": {
        "title": "Backup Retention & Immutability Lifecycle",
        "mappings": {"NIST": "PR.DS-P11", "ISO": "A.8.13", "DESC_ISR": "Domain 5"},
        "remediation": "🚨 FIX ACTION: Update your backup policy object. Set 'retention_days' to 90 or higher and ensure 'encryption_algorithm' is strictly set to 'AES-256'."
    },
    "CONTROL-03": {
        "title": "Continuous Vulnerability Management Pipeline",
        "mappings": {"NIST": "DE.CM-P1", "ISO": "A.8.8", "DESC_ISR": "Domain 9"},
        "remediation": "🚨 FIX ACTION: Edit your automated pipeline steps array. Add a security scanning stage containing 'trivy', 'nessus', or 'sonar' binaries."
    }
}

def analyze_advanced_config(file_obj):
    if file_obj is None:
        return "Please upload an enterprise configuration JSON file.", "", ""
    
    try:
        with open(file_obj.name, 'r') as f:
            data = json.load(f)
            
        detected_statuses = {}

        iam = data.get("identity_management", {})
        root_mfa = iam.get("root_user", {}).get("mfa_enabled", False)

        has_wildcard_policy = False
        for role in iam.get("user_roles", []):
            if "*" in role.get("permissions", []):
                has_wildcard_policy = True
                
        if root_mfa and not has_wildcard_policy:
            detected_statuses["CONTROL-01"] = "COMPLIANT"
        else:
            detected_statuses["CONTROL-01"] = "NON_COMPLIANT"

        backups = data.get("backup_lifecycle", {})
        retention = backups.get("retention_days", 0)
        encryption = backups.get("encryption_algorithm", "")

        if retention >= 90 and encryption == "AES-256":
            detected_statuses["CONTROL-02"] = "COMPLIANT"
        else:
            detected_statuses["CONTROL-02"] = "NON_COMPLIANT"

        pipeline_stages = data.get("deployment_pipeline", {}).get("stages", [])

        approved_scanners = ["trivy", "nessus", "aquasec", "snyk"]
        scanner_detected = any(scanner in [stage.lower() for stage in pipeline_stages] for scanner in approved_scanners)
        
        if scanner_detected:
            detected_statuses["CONTROL-03"] = "COMPLIANT"
        else:
            detected_statuses["CONTROL-03"] = "NON_COMPLIANT"

    except Exception as e:
        return f"❌ Parsing Error: Ensure valid structure. Details: {str(e)}", "", ""

    total = len(COMPLIANCE_DATABASE)
    passed = sum(1 for s in detected_statuses.values() if s == "COMPLIANT")
    pct = (passed / total) * 100
    
    summary_text = f"📊 Posture Status: {pct:.1f}% Compliant ({passed}/{total} Passed)\n" \
                   f" • NIST CSF v2.0: {pct:.1f}%\n" \
                   f" • ISO/IEC 27001:2022: {pct:.1f}%\n" \
                   f" • Dubai DESC ISR v3.0: {pct:.1f}%"

    remediation_playbook = ""
    findings = {}
    for cid, meta in COMPLIANCE_DATABASE.items():
        status = detected_statuses[cid]
        findings[cid] = {"title": meta["title"], "status": status, "mappings": meta["mappings"]}
        if status == "NON_COMPLIANT":
            remediation_playbook += f"### {cid}: {meta['title']}\n* **Gaps Identified:** Failed specific technical validation criteria.\n* {meta['remediation']}\n\n"

    if not remediation_playbook:
        remediation_playbook = "✅ **Compliance Confirmed.** All advanced schema controls passed policy thresholds."

    report = {"summary": {"NIST": f"{pct}%", "ISO": f"{pct}%", "DESC": f"{pct}%"}, "findings": findings}
    return summary_text, remediation_playbook, json.dumps(report, indent=2)

with gr.Blocks(title="Advanced Tech GRC Compliance Auditor") as demo:
    gr.Markdown("# 🛡️ Automated Multi-Framework Regulatory Compliance Auditor")
    gr.Markdown("Parses nested configuration objects, validates security arrays, and analyzes control logic thresholds.")
    
    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(label="Upload complex_system_state.json", file_types=[".json"])
            submit_btn = gr.Button("Execute Deep Compliance Scan", variant="primary")
        with gr.Column(scale=1):
            output_summary = gr.Textbox(label="Executive Readiness Summary", lines=5)
            
    gr.Markdown("---")
    with gr.Row():
        with gr.Column(scale=1):
            output_remediation = gr.Markdown(value="*Upload configuration file to generate playbooks...*")
        with gr.Column(scale=1):
            output_json = gr.Code(label="compliance_gap_analysis.json", language="json")

    submit_btn.click(fn=analyze_advanced_config, inputs=[file_input], outputs=[output_summary, output_remediation, output_json])

if __name__ == "__main__":
    demo.launch()