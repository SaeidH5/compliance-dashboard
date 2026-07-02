import os
import json
import gradio as gr

def analyze_advanced_config(config_json):
    """
    Advanced Compliance Engine that evaluates deep nested objects,
    array token validation, and administrative wildcard privileges.
    """
    findings = []
    total_controls = 4
    passed_controls = 0

    try:
        iam_roles = config_json.get("identity_management", {}).get("roles", [])
        wildcard_found = False
        for role in iam_roles:
            for policy in role.get("policies", []):
                if "*" in policy.get("permissions", []):
                    wildcard_found = True
                    findings.append({
                        "id": "NIST-CM-5 / DESC-ISR-11.1",
                        "frameworks": ["NIST CSF v2.0", "Dubai DESC ISR v3.0"],
                        "status": "FAILED",
                        "details": f"Privilege escalation risk: Role '{role.get('role_name')}' contains an unmanaged administrative wildcard (*) policy statement."
                    })
                    break
        if not wildcard_found:
            passed_controls += 1
    except Exception:
        findings.append({"id": "IAM-SCAN-ERR", "frameworks": ["ALL"], "status": "FAILED", "details": "Error parsing IAM roles object hierarchy."})

    try:
        deploy_pipeline = config_json.get("deployment_pipeline", {})
        scanners = deploy_pipeline.get("security_scanners", [])
        required_scanners = {"trivy", "nessus"}

        found_tokens = {str(s).lower() for s in scanners}
        missing_scanners = required_scanners - found_tokens

        if missing_scanners:
            findings.append({
                "id": "ISO-A.14.1.1 / DESC-ISR-15.2",
                "frameworks": ["ISO/IEC 27001:2022", "Dubai DESC ISR v3.0"],
                "status": "FAILED",
                "details": f"Missing authorized security testing binaries in deployment arrays. Missing: {', '.join(missing_scanners)}."
            })
        else:
            passed_controls += 1
    except Exception:
        findings.append({"id": "SCANNER-ARR-ERR", "frameworks": ["ALL"], "status": "FAILED", "details": "Deployment pipeline token scanning failed."})

    try:
        backup_policy = config_json.get("infrastructure_state", {}).get("backup_policy", {})
        retention_days = backup_policy.get("retention_days", 0)
        encrypted = backup_policy.get("encrypted", False)

        if retention_days < 90 or not encrypted:
            details_msg = f"Backup configuration threshold breach: Retention window is {retention_days} days (Req: >=90) and Encryption is {encrypted}."
            findings.append({
                "id": "ISO-A.12.3.1",
                "frameworks": ["ISO/IEC 27001:2022"],
                "status": "FAILED",
                "details": details_msg
            })
        else:
            passed_controls += 1
    except Exception:
        findings.append({"id": "BACKUP-THRES-ERR", "frameworks": ["ALL"], "status": "FAILED", "details": "Infrastructure state threshold verification failed."})

    try:
        storage = config_json.get("infrastructure_state", {}).get("storage", {})
        if not storage.get("encryption_at_rest", False):
            findings.append({
                "id": "NIST-PR.DS-1 / DESC-ISR-13.1",
                "frameworks": ["NIST CSF v2.0", "Dubai DESC ISR v3.0"],
                "status": "FAILED",
                "details": f"Critical asset storage block '{storage.get('volume_id', 'Unknown')}' is operating without AES-256 data-at-rest cryptographic enforcement."
            })
        else:
            passed_controls += 1
    except Exception:
        findings.append({"id": "CRYPTO-ERR", "frameworks": ["ALL"], "status": "FAILED", "details": "Storage encryption parameter evaluation failed."})

    pct = int((passed_controls / total_controls) * 100)

    # Compile the human-readable UI text output
    summary_text = f"### Overall System Compliance Score: {pct}%\n"
    summary_text += f"- **Passed Controls:** {passed_controls} / {total_controls}\n"
    summary_text += f"- **Status:** {'⚠️ COMPLIANCE GAP IDENTIFIED' if pct < 100 else '✅ SYSTEM SECURE'}\n"

    playbook_text = "## 🛠️ Dynamic Technical Remediation Playbook\n\n"
    if pct == 100:
        playbook_text += "🎉 All evaluated infrastructure controls conform fully to NIST, ISO, and DESC specifications."
    else:
        for item in findings:
            playbook_text += f"### ❌ Action Required: {item['id']}\n"
            playbook_text += f"**Frameworks:** {', '.join(item['frameworks'])}\n"
            playbook_text += f"**Issue:** {item['details']}\n\n"
            
            if "IAM" in item['id'] or "CM-5" in item['id']:
                playbook_text += "👉 **Remediation:** Locate the IAM deployment configuration file. Strip the `*` wildcard element out of the permissions array block and apply a strict Principle of Least Privilege role mapping layout.\n\n"
            elif "ISO-A.14" in item['id']:
                playbook_text += "👉 **Remediation:** Append `'trivy'` and `'nessus'` directly into the `security_scanners` deployment array string configurations inside your CI/CD platform configs.\n\n"
            elif "A.12.3" in item['id']:
                playbook_text += "👉 **Remediation:** Adjust your infrastructure state template variables: modify `retention_days` to integer `90` or higher and confirm boolean key flag `\"encrypted\": true`.\n\n"
            elif "PR.DS-1" in item['id']:
                playbook_text += "👉 **Remediation:** Apply block storage encryption profiles utilizing cloud Key Management Service (KMS) or standard provider cryptographic defaults.\n\n"
            playbook_text += "---\n\n"

    report_artifact = {
        "summary": {
            "global_score_percentage": pct,
            "passed_controls": passed_controls,
            "total_controls": total_controls,
            "framework_mappings": {
                "NIST_CSF_v2.0": f"{pct}%",
                "ISO_IEC_27001_2022": f"{pct}%",
                "Dubai_DESC_ISR_v3.0": f"{pct}%"
            }
        },
        "findings": findings
    }

    with open("compliance_gap_analysis.json", "w") as out_file:
        json.dump(report_artifact, out_file, indent=4)

    return summary_text, playbook_text, json.dumps(report_artifact, indent=4)

def gradio_wrapper(file_obj):
    """Wrapper function to read uploaded Gradio file object safely"""
    if file_obj is None:
        return "### ❌ Error\nNo configuration evidence file uploaded.", "", "{}"
    try:
        with open(file_obj.name, 'r') as f:
            data = json.load(f)
        return analyze_advanced_config(data)
    except Exception as e:
        return f"### ❌ File Error\nFailed to parse JSON target file structure: {str(e)}", "", "{}"

with gr.Blocks(title="Multi-Framework Compliance Engine") as demo:
    gr.Markdown("# 🛡️ Continuous Multi-Framework Regulatory Compliance Dashboard")
    gr.Markdown("Ingest configuration states dynamically to map security postures against **NIST CSF v2.0**, **ISO/IEC 27001:2022**, and **Dubai DESC ISR v3.0** models.")
    
    with gr.Row():
        with gr.Column(scale=1):
            file_input = gr.File(label="Ingest Audit Configuration Evidence (system_state.json)")
            btn = gr.Button("Execute Deep Compliance Scan", variant="primary")
        
        with gr.Column(scale=2):
            summary_out = gr.Markdown(value="### System Metrics\nUpload data and run assessment matrix.")
            playbook_out = gr.Markdown(value="## Technical Remediation Playbooks\nAwaiting target validation run execution...")
            json_out = gr.Code(label="Exportable Compliance Gap Analysis JSON Artifact", language="json")

    btn.click(fn=gradio_wrapper, inputs=file_input, outputs=[summary_out, playbook_out, json_out])

if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("🚀 GitHub Actions Pipeline environment detected! Booting headless scan runner...")
        
        try:
            with open("system_state.json", "r") as f:
                mock_evidence = json.load(f)
            
            # Execute logic directly; this automatically updates compliance_gap_analysis.json
            analyze_advanced_config(mock_evidence)
            print("✅ Continuous Compliance Pipeline run successful! Report artifact created.")
            
        except FileNotFoundError:
            print("❌ Execution Terminal Failure: 'system_state.json' target element absent from repository framework.")
            exit(1)
    else:
        print("🖥️ Local workstation environment detected! Launching Interactive Web Application UI...")
        demo.launch()