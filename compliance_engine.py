import json
import sys

COMPLIANCE_MATRIX = {
    "CONTROL-01": {
        "title": "Multi-Factor Authentication (MFA) Implementation",
        "description": "Enforce MFA for all remote, administrative, and privileged infrastructure access.",
        "mappings": {
            "NIST_CSF_v2": "PR.AA-P1",
            "ISO_27001_2022": "A.5.15",
            "DESC_ISR_v3": "Domain 6 (Access Control)"
        }
    },
    "CONTROL-02": {
        "title": "Immutable Backup Configuration",
        "description": "Maintain isolated, encrypted backups with strict retention policies to resist ransomware.",
        "mappings": {
            "NIST_CSF_v2": "PR.DS-P11",
            "ISO_27001_2022": "A.8.13",
            "DESC_ISR_v3": "Domain 5 (Communications & Operations)"
        }
    },
    "CONTROL-03": {
        "title": "Continuous Vulnerability Management Pipeline",
        "description": "Execute quarterly external network scans and validate code vulnerabilities via automated CI pipelines.",
        "mappings": {
            "NIST_CSF_v2": "DE.CM-P1",
            "ISO_27001_2022": "A.8.8",
            "DESC_ISR_v3": "Domain 9 (Operations Security)"
        }
    },
    "CONTROL-04": {
        "title": "Incident Response Plan & Cyber Drill Validation",
        "description": "Maintain a fully documented incident plan with annual simulation drills.",
        "mappings": {
            "NIST_CSF_v2": "RS.RP-P1",
            "ISO_27001_2022": "A.5.24",
            "DESC_ISR_v3": "Domain 11 (Incident Management)"
        }
    }
}

AUDIT_EVIDENCE_STATUS = {
    "CONTROL-01": "COMPLIANT",
    "CONTROL-02": "NON_COMPLIANT", 
    "CONTROL-03": "COMPLIANT",
    "CONTROL-04": "COMPLIANT"
}

def calculate_framework_readiness():
    framework_scores = {
        "NIST_CSF_v2": {"passed": 0, "total": 0},
        "ISO_27001_2022": {"passed": 0, "total": 0},
        "DESC_ISR_v3": {"passed": 0, "total": 0}
    }
    
    detailed_findings = {}

    for ctrl_id, ctrl_meta in COMPLIANCE_MATRIX.items():
        status = AUDIT_EVIDENCE_STATUS.get(ctrl_id, "NON_COMPLIANT")
        is_passed = 1 if status == "COMPLIANT" else 0
        
        detailed_findings[ctrl_id] = {
            "title": ctrl_meta["title"],
            "status": status,
            "mapped_requirements": ctrl_meta["mappings"]
        }

        for framework in framework_scores.keys():
            if framework in ctrl_meta["mappings"]:
                framework_scores[framework]["total"] += 1
                framework_scores[framework]["passed"] += is_passed

    readiness_summary = {}
    for fw, counts in framework_scores.items():
        percentage = (counts["passed"] / counts["total"] * 100) if counts["total"] > 0 else 0
        readiness_summary[fw] = f"{percentage:.1f}% Ready ({counts['passed']}/{counts['total']} Controls)"

    return {
        "executive_readiness_summary": readiness_summary,
        "granular_compliance_findings": detailed_findings
    }

def main():
    print("[+] Initiating Cross-Framework Compliance Gap Assessment Engine...")
    report = calculate_framework_readiness()
    
    print("\n================ EXECUTIVE DASHBOARD POSTURE BRIEF ================")
    for framework, baseline in report["executive_readiness_summary"].items():
        print(f" [*] {framework}: {baseline}")
    print("===================================================================\n")
    
    output_file = "compliance_gap_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=4)
        
    print(f"[SUCCESS] Compliance artifacts archived to: {output_file}")

if __name__ == "__main__":
    main()