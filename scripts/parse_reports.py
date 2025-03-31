import json
import os

def parse_trivy_results(file_path, scan_type):
    if not os.path.exists(file_path):
        return {
            "tool": "Trivy",
            "type": scan_type,
            "results": [],
            "note": f"File {file_path} not found."
        }

    with open(file_path, 'r') as f:
        sarif = json.load(f)

    results = []
    rules_map = {}

    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.get("rules", [])
        for rule in rules:
            rules_map[rule.get("id")] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            rule = rules_map.get(rule_id, {})
            help_text = rule.get("help", {}).get("markdown", "")

            # 尝试提取修复建议
            fix_info = ""
            if "|LOW|" in help_text or "|HIGH|" in help_text or "|CRITICAL|" in help_text:
                fix_info = help_text.split("\n")[-1].strip()

            results.append({
                "tool": "Trivy",
                "type": scan_type,
                "cve": rule.get("id"),
                "component": rule.get("help", {}).get("text", "").split("Package:")[-1].split("\n")[0].strip(),
                "severity": rule.get("properties", {}).get("security-severity", "N/A"),
                "description": rule.get("shortDescription", {}).get("text", ""),
                "remediation": fix_info,
                "reference": rule.get("helpUri", "")
            })

    return {
        "tool": "Trivy",
        "type": scan_type,
        "results": results
    }

def parse_zap_results(zap_file_path):
    if not os.path.exists(zap_file_path):
        return {
            "tool": "OWASP ZAP",
            "type": "dast",
            "results": [],
            "note": f"File {zap_file_path} not found."
        }

    with open(zap_file_path, 'r') as f:
        zap_json = json.load(f)

    results = []

    for site in zap_json.get("site", []):
        alerts = site.get("alerts", [])
        for alert in alerts:
            for instance in alert.get("instances", []):
                results.append({
                    "tool": "OWASP ZAP",
                    "type": "dast",
                    "name": alert.get("name"),
                    "risk": alert.get("riskdesc"),
                    "description": alert.get("desc"),
                    "uri": instance.get("uri"),
                    "evidence": instance.get("evidence"),
                    "solution": alert.get("solution"),
                    "cwe": alert.get("cweid"),
                })

    return {
        "tool": "OWASP ZAP",
        "type": "dast",
        "results": results
    }

# ==== 主程序入口 ====
if __name__ == "__main__":
    merged-security-reports = []

    merged-security-reports.append(parse_trivy_results("trivy-fs-results.sarif", scan_type="sca-fs"))
    merged-security-reports.append(parse_trivy_results("trivy-results.sarif", scan_type="sca-image"))
    merged-security-reports.append(parse_zap_results("report_json.json"))

    with open("merged-security-reports.json", "w") as f:
        json.dump(merged-security-reports, f, indent=2)

    print("✅ Merged report written to merged-security-reports.json")
