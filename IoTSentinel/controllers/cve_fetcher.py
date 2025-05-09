import requests
import json
import os
from cvss_scoring import calculate_cvss  # Import CVSS scoring function

class CVEFetcher:
    def __init__(self):
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "cve_data.json")
        self.temp_file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "cve_temp.json")  # Temp file
        self.default_params = {
            "keywordSearch": "IoT",
            "resultsPerPage": 10,
            "startIndex": 0
        }

    def fetch_cve_by_keyword(self):
        """Fetch CVEs using keyword search and save raw response for debugging."""
        try:
            response = requests.get(self.api_url, params=self.default_params)
            if response.status_code == 200:
                cve_data = response.json()
                self.save_raw_cve_data(cve_data)

                return self.extract_cvss_info(cve_data.get("vulnerabilities", []))
            else:
                print(f"Error fetching CVE data: {response.status_code}")
                return []
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}")
            return []

    def save_raw_cve_data(self, cve_data):
        """Save raw API response to a temporary file for debugging."""
        try:
            with open(self.temp_file_path, "w", encoding="utf-8") as temp_file:
                json.dump(cve_data, temp_file, indent=4)
            print(f"Raw CVE data saved successfully in {self.temp_file_path}.")
        except IOError as e:
            print(f"File write error (temp file): {e}")

    def extract_cvss_info(self, vulnerabilities):
        """Extract CVSS vectors and compute scores from the vulnerabilities list."""
        processed_cves = []
        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "Unknown")

            # Identify CVSS schema type and extract corresponding data
            metrics = cve_item.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_schema = "CVSSv3.1"
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            elif "cvssMetricV30" in metrics:
                cvss_schema = "CVSSv3.0"
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            elif "cvssMetricV2" in metrics:
                cvss_schema = "CVSSv2.0"
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            else:
                cvss_schema = "Unknown"
                cvss_data = {}

            vector_string = cvss_data.get("vectorString", None)
            base_score = cvss_data.get("baseScore", None)

            if vector_string:
                cvss_vector = self.parse_vector_string(cvss_data, cvss_schema)
                cvss_score = calculate_cvss(cvss_vector) if cvss_vector else base_score
            else:
                print(f"Warning: CVE {cve_id} lacks CVSS vectorString, falling back to baseScore.")
                cvss_vector, cvss_score = None, base_score

            processed_cves.append({
                "id": cve_id,
                "description": cve_item.get("descriptions", [{}])[0].get("value", "No description available."),
                "cvss_schema": cvss_schema,
                "cvss_vector": vector_string if vector_string else "N/A",
                "cvss_score": cvss_score if cvss_score is not None else "N/A"
            })

        return processed_cves

    def parse_vector_string(self, cvss_data, schema):
        """Convert CVSS fields from NIST API based on schema version."""
        schema_mapping = {
            "CVSSv3.1": {
                "AV": "attackVector",
                "AC": "attackComplexity",
                "PR": "privilegesRequired",
                "UI": "userInteraction",
                "S": "scope",
                "C": "confidentialityImpact",
                "I": "integrityImpact",
                "A": "availabilityImpact",
            },
            "CVSSv3.0": {
                "AV": "attackVector",
                "AC": "attackComplexity",
                "PR": "privilegesRequired",
                "UI": "userInteraction",
                "S": "scope",
                "C": "confidentialityImpact",
                "I": "integrityImpact",
                "A": "availabilityImpact",
            },
            "CVSSv2.0": {
                "AV": "accessVector",
                "AC": "accessComplexity",
                "PR": "authentication",
                "UI": "userInteractionRequired",
                "C": "confidentialityImpact",
                "I": "integrityImpact",
                "A": "availabilityImpact",
            }
        }

        numerical_mapping = {
            "HIGH": 0.56, "LOW": 0.42, "NONE": 0.0,
            "NETWORK": 0.85, "ADJACENT_NETWORK": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2,
            "LOW": 0.71, "HIGH": 0.35,
            "NONE": 0.85, "LOW": 0.62, "HIGH": 0.27,
            "NONE": 0.85, "REQUIRED": 0.62
        }

        mapping = schema_mapping.get(schema, {})
        parsed_vector = {}

        for key, api_field in mapping.items():
            value = cvss_data.get(api_field, "NONE")
            parsed_vector[key] = numerical_mapping.get(value, 0.0)

        return parsed_vector

    def save_cve_data(self, cve_data):
        """Save processed CVE data including CVSS scores."""
        try:
            os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as file:
                json.dump(cve_data, file, indent=4)
            print(f"CVE data saved successfully with CVSS scores in {self.file_path}.")
        except IOError as e:
            print(f"File write error: {e}")

if __name__ == "__main__":
    fetcher = CVEFetcher()
    cve_list = fetcher.fetch_cve_by_keyword()
    fetcher.save_cve_data(cve_list)  # ✅ Ensure `save_cve_data()` is correctly referenced
