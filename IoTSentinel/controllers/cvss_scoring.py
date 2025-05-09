import json
import math

def calculate_cvss(cvss_vector):
    """
    Calculate CVSS score based on the provided vector dictionary.
    Example dictionary:
    {"AV": 0.85, "AC": 0.71, "PR": 0.85, "UI": 0.85, "S": "U", "C": 0.56, "I": 0.56, "A": 0.56}
    """

    # Ensure scope is properly handled
    scope = cvss_vector.get("S", "U")  # Default to "U" if missing
    impact_subscore = 1 - (1 - cvss_vector["C"]) * (1 - cvss_vector["I"]) * (1 - cvss_vector["A"])

    if scope == "U":  # Unchanged Scope
        impact_score = 6.42 * impact_subscore
    elif scope == "C":  # Changed Scope
        impact_score = 7.52 * (impact_subscore - 0.029) - 3.25 * math.pow(impact_subscore - 0.02, 15)
    else:
        print(f"Warning: Unexpected scope '{scope}', defaulting to Unchanged.")
        impact_score = 6.42 * impact_subscore  # Default to Unchanged scope

    exploitability_score = (
        8.22 * cvss_vector["AV"] * cvss_vector["AC"] * cvss_vector["PR"] * cvss_vector["UI"]
    )

    base_score = min(math.ceil(impact_score + exploitability_score), 10.0)
    return base_score


def classify_severity(cvss_score):
    """
    Assign severity classification based on CVSS score.
    """
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score > 0.0:
        return "Low"
    else:
        return "None"


def process_cve_data(cve_file="cve_data.json"):
    """
    Load CVE data, calculate CVSS scores, assign severity labels, and save sorted data.
    """

    # Load CVE data
    with open(cve_file, "r", encoding="utf-8") as file:
        cve_entries = json.load(file)

    # Process and classify each CVE entry
    for cve in cve_entries:
        if "cvss_vector" in cve and isinstance(cve["cvss_vector"], str):  # Ensure data is a string
            vector_parts = cve["cvss_vector"].split("/")
            parsed_vector = {
                "AV": 0.85 if "AV:N" in vector_parts else 0.62 if "AV:A" in vector_parts else 0.55 if "AV:L" in vector_parts else 0.2,
                "AC": 0.71 if "AC:L" in vector_parts else 0.35,
                "PR": 0.85 if "PR:N" in vector_parts else 0.62 if "PR:L" in vector_parts else 0.27,
                "UI": 0.85 if "UI:N" in vector_parts else 0.62,
                "S": "C" if "S:C" in vector_parts else "U",
                "C": 0.56 if "C:H" in vector_parts else 0.42 if "C:L" in vector_parts else 0.0,
                "I": 0.56 if "I:H" in vector_parts else 0.42 if "I:L" in vector_parts else 0.0,
                "A": 0.56 if "A:H" in vector_parts else 0.42 if "A:L" in vector_parts else 0.0,
            }
            cve["cvss_score"] = calculate_cvss(parsed_vector)
            cve["severity"] = classify_severity(cve["cvss_score"])

    # **Sort vulnerabilities** from highest severity to lowest
    cve_entries.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

    # Save updated and sorted CVE data
    with open(cve_file, "w", encoding="utf-8") as file:
        json.dump(cve_entries, file, indent=4)

    print(f"[SUCCESS] CVE data sorted by severity and saved successfully in {cve_file}.")


if __name__ == "__main__":
    process_cve_data()
