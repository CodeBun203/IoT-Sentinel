# /home/mininet/IoTSentinel/scanners/cve_fetcher.py
import requests
import json
import os
import sys

class CVEFetcher:
    def __init__(self, keyword="IoT", results_per_page=5):
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page
        }
        # Base path for IoTSentinel project to construct file paths if needed
        # self.project_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        # self.file_path = os.path.join(self.project_base_dir, "controllers", "cve_data.json") # If saving

    def fetch_cve_data(self):
        try:
            response = requests.get(self.api_url, params=self.params)
            response.raise_for_status()  # Raises an HTTPError for bad responses (4XX or 5XX)
            cve_data = response.json()
            
            processed_cves = []
            for vuln in cve_data.get("vulnerabilities", []):
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "Unknown CVE ID")
                description = "No description available."
                # Get English description
                for desc_entry in cve_item.get("descriptions", []):
                    if desc_entry.get("lang") == "en":
                        description = desc_entry.get("value", description)
                        break
                
                base_score = "N/A"
                # Try CVSS v3.1 then v3.0 then v2.0
                metrics = cve_item.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    base_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "N/A")
                elif "cvssMetricV30" in metrics:
                    base_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", "N/A")
                elif "cvssMetricV2" in metrics:
                    base_score = metrics["cvssMetricV2"][0].get("baseScore", "N/A") # V2 structure is a bit different

                processed_cves.append({
                    "id": cve_id,
                    "description": description,
                    "score": base_score,
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
            return processed_cves
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err} - {response.status_code} - {response.text}", file=sys.stderr)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE data: {e}", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response: {e}", file=sys.stderr)
        return []

if __name__ == "__main__":
    search_keyword = "IoT"  # Default keyword
    if len(sys.argv) > 1:
        search_keyword = sys.argv[1]
    
    fetcher = CVEFetcher(keyword=search_keyword)
    cves = fetcher.fetch_cve_data()
    print(json.dumps(cves, indent=2)) # Output JSON to stdout
