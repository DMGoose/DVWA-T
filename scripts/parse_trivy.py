import json
import os

# Define input SARIF file paths
fs_sarif_path = "trivy-fs-results.sarif"
image_sarif_path = "trivy-results.sarif"

# Define output path
output_path = "merged-trivy.json"

# Function to extract results from SARIF file
def extract_trivy_results(sarif_path, scan_type):
    if not os.path.exists(sarif_path):
        return {
            "tool": "Trivy",
            "type": scan_type,
            "results": [],
            "note": f"File {sarif_path} not found."
        }

    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    results = []
    try:
        rules = {}
        for rule in sarif_data["runs"][0]["tool"]["driver"].get("rules", []):
            rules[rule["id"]] = rule

        for result in sarif_data["runs"][0].get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            vuln = {
                "tool": "Trivy",
                "type": scan_type,
                "id": rule.get("id", ""),
                "cve": rule.get("id", ""),
                "severity": rule.get("properties", {}).get("security-severity", ""),
                "package": rule.get("help", {}).get("text", "").split("Package: ")[-1].split("\n")[0] if "Package:" in rule.get("help", {}).get("text", "") else "",
                "description": rule.get("fullDescription", {}).get("text", ""),
                "recommendation": rule.get("helpUri", ""),
                "link": rule.get("helpUri", "")
            }
            results.append(vuln)
    except Exception as e:
        return {
            "tool": "Trivy",
            "type": scan_type,
            "results": [],
            "error": str(e)
        }

    return {
        "tool": "Trivy",
        "type": scan_type,
        "results": results
    }

# Extract results
fs_results = extract_trivy_results(fs_sarif_path, "sca-fs")
image_results = extract_trivy_results(image_sarif_path, "sca-image")

# Combine and save
merged = [fs_results, image_results]

with open("merged-trivy.json", "w") as outfile:
    json.dump(merged, out_file, indent=2)

print("✅ Merged Trivy results saved to merged-trivy.json")
