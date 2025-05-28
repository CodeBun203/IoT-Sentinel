from flask import Flask, jsonify, request, abort
from flask_cors import CORS
import json
import os
import subprocess

app = Flask(__name__)
CORS(app)

# --- File Paths ---
# Base path for IoTSentinel project to construct file paths
iot_sentinel_base_path = os.path.abspath(os.path.join(os.path.dirname(__file__))) # Assumes main.py is in IoTSentinel root

LATEST_EVENTS_PATH = os.path.join(iot_sentinel_base_path, "logs/latest_events.json")
MASTER_LOG_PATH = os.path.join(iot_sentinel_base_path, "logs/master_event_log.json")
COMMAND_QUEUE_PATH = os.path.join(iot_sentinel_base_path, "logs/command_queue.json")
NETWORK_TOPOLOGY_PATH = os.path.join(iot_sentinel_base_path, "logs/network_topology.json")
CVE_FETCHER_SCRIPT_PATH = os.path.join(iot_sentinel_base_path, "scanners/cve_fetcher.py")

# --- API Endpoints ---
@app.route('/api/dashboard', methods=['GET'])
def get_dashboard_events():
    try:
        with open(LATEST_EVENTS_PATH, 'r') as f:
            events = json.load(f)
        return jsonify(events)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({"timestamp": "N/A", "events": []}) # Return empty structure if no data

@app.route('/api/logs', methods=['GET'])
def get_log_events():
    try:
        with open(MASTER_LOG_PATH, 'r') as f:
            log_data = json.load(f)
        return jsonify(log_data)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify([]) # Return empty list if no logs

@app.route('/api/network_topology', methods=['GET'])
def get_network_topology():
    try:
        with open(NETWORK_TOPOLOGY_PATH, 'r') as f:
            topology = json.load(f)
        return jsonify(topology)
    except (FileNotFoundError, json.JSONDecodeError):
        return jsonify({"nodes": [], "links": []}) # Return empty structure

@app.route('/api/fix', methods=['POST'])
def issue_fix_command():
    vulnerability_data = request.get_json()
    if not vulnerability_data or not isinstance(vulnerability_data, dict):
        return jsonify({"error": "Invalid request data"}), 400
    try:
        with open(COMMAND_QUEUE_PATH, 'a') as f: # Append mode
            f.write(json.dumps(vulnerability_data) + '\n')
        return jsonify({"message": "Fix command queued successfully."}), 202
    except Exception as e:
        app.logger.error(f"Error writing to command queue: {e}")
        return jsonify({"error": "Failed to queue fix command"}), 500

@app.route('/api/cve_info', methods=['GET'])
def get_cve_info():
    keywords = request.args.get('keywords', default="IoT vulnerability", type=str)
    if not keywords:
        return jsonify({"error": "Keywords parameter is required."}), 400

    try:
        # Ensure the script path is correct and executable
        if not os.path.exists(CVE_FETCHER_SCRIPT_PATH):
             app.logger.error(f"CVE Fetcher script not found at {CVE_FETCHER_SCRIPT_PATH}")
             return jsonify({"error": "CVE Fetcher script not found."}), 500

        # Use subprocess to run the cve_fetcher.py script
        # Pass keywords as a command line argument
        process = subprocess.run(
            ['python3', CVE_FETCHER_SCRIPT_PATH, keywords],
            capture_output=True,
            text=True,
            check=False, # Don't raise exception for non-zero exit codes
            timeout=30  # Add a timeout
        )
        
        if process.returncode != 0:
            app.logger.error(f"CVE Fetcher script error: {process.stderr}")
            return jsonify({"error": "Failed to fetch CVE info.", "details": process.stderr}), 500
        
        try:
            cve_data = json.loads(process.stdout)
            return jsonify(cve_data)
        except json.JSONDecodeError:
            app.logger.error(f"Failed to parse JSON from CVE Fetcher: {process.stdout}")
            return jsonify({"error": "Failed to parse CVE info from script."}), 500

    except subprocess.TimeoutExpired:
        app.logger.error("CVE Fetcher script timed out.")
        return jsonify({"error": "CVE Fetcher script timed out."}), 500
    except Exception as e:
        app.logger.error(f"Error running CVE Fetcher script: {e}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    # Ensure logs directory exists
    logs_dir = os.path.join(iot_sentinel_base_path, "logs")
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    app.run(host='0.0.0.0', port=5001, debug=True)
