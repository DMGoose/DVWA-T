import json
import os

def parse_trivy_sarif(sarif_path):
    with open(sarif_path, 'r', encoding='utf-8') as file:
        data = json.load(file)

    output = []
    for run in data.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "Trivy")
        rules = {rule["id"]: rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        results = run.get("results", [])

        for result in results:
            rule_id = result.get("ruleId")
            rule = rules.get(rule_id, {})
            output.append({
                "source": tool_name,
                "component": rule.get("properties", {}).get("package", "N/A"),
                "cve": rule.get("id", "N/A"),
                "severity": rule.get("properties", {}).get("severity", "N/A"),
                "description": rule.get("fullDescription", {}).get("text", ""),
                "link": rule.get("helpUri", ""),
                "recommendation": rule.get("help", {}).get("text", ""),
                "location": result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A")
            })

    return output

# Example test on a placeholder path
example_path = "/mnt/data/trivy-results.sarif"
if os.path.exists(example_path):
    parsed_results = parse_trivy_sarif(example_path)
    output_path = "/mnt/data/merged-trivy.json"
    with open(output_path, 'w', encoding='utf-8') as out_file:
        json.dump(parsed_results, out_file, indent=2)
    output_path
else:
    "SARIF file not found."
