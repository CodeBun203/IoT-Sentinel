# /home/mininet/IoTSentinel/fixers/ddos_fixer.py
import json
import sys
import os

def analyze_dos_data_and_suggest_blocks(scan_result_data):
    """
    Analyzes the DoS/DDoS scanner output/internal detection data and suggests IPs to block.
    Args:
        scan_result_data (dict): The JSON data detailing the potential attack.
    Returns:
        list: A list of IPs suggested for blocking.
    """
    ips_to_block = []
    target_ip = scan_result_data.get("ip")
    # "prominent_sources" should be a list of dicts, e.g., [{"ip": "1.2.3.4", "count": X}]
    # or just [{"ip": "1.2.3.4"}] if count is not easily available from detector
    prominent_sources = scan_result_data.get("prominent_sources", [])
    source_ip_count = scan_result_data.get("source_ip_count", 0) # May not be available from all internal detectors
    packet_count = scan_result_data.get("packet_count", 0) # May not be available from all internal detectors
    vuln_type = scan_result_data.get("vulnerability", "unknown_dos_event")

    print(f"[ddos_fixer_stderr] Analyzing DoS data for target {target_ip} (type: {vuln_type}). Packets: {packet_count}, Sources: {source_ip_count}.", file=sys.stderr)

    # Simple strategy: if prominent_sources are identified, block them.
    if prominent_sources:
        for source_info in prominent_sources:
            source_ip_to_block = source_info.get("ip")
            if source_ip_to_block and source_ip_to_block != target_ip: # Don't block the victim
                if source_ip_to_block not in ips_to_block: # Avoid duplicates
                    ips_to_block.append(source_ip_to_block)
                    print(f"[ddos_fixer_stderr] Suggesting to block prominent source: {source_ip_to_block} for attack on {target_ip}", file=sys.stderr)
            elif not source_ip_to_block:
                print(f"[ddos_fixer_stderr] Found a prominent source entry without an IP: {source_info}", file=sys.stderr)


    # If no prominent sources explicitly listed but it's a flood type,
    # this fixer currently doesn't have enough info to pick specific IPs.
    # The internal detector in mqtt_monitor might provide the single source IP if it's a simple flood.
    if not ips_to_block and "flood" in vuln_type.lower():
         print(f"[ddos_fixer_stderr] High traffic volume ({vuln_type}) on {target_ip}. 'prominent_sources' list was empty or non-actionable. Fixer relies on POX module for source identification from packet if not provided.", file=sys.stderr)

    return ips_to_block

if __name__ == "__main__":
    fix_result = {
        "fixer_script": "ddos_fixer.py",
        "target_ip": "N/A",
        "vulnerability_type": "N/A",
        "action_attempted": "suggest_ip_blocks_for_dos_mitigation",
        "success": False,
        "message": "Fixer not properly invoked or missing scan data.",
        "ips_suggested_for_blocking": []
    }

    if len(sys.argv) > 1:
        try:
            scan_data_json = sys.argv[1]
            scan_data = json.loads(scan_data_json)
            
            fix_result["target_ip"] = scan_data.get("ip", "N/A")
            fix_result["vulnerability_type"] = scan_data.get("vulnerability", "N/A")
            print(f"[ddos_fixer_main] ddos_fixer.py invoked for target {fix_result['target_ip']}, vuln: {fix_result['vulnerability_type']}", file=sys.stderr)

            suggested_blocks = analyze_dos_data_and_suggest_blocks(scan_data)
            
            if suggested_blocks:
                fix_result["success"] = True
                fix_result["message"] = f"Suggested blocking {len(suggested_blocks)} IP(s) targeting {fix_result['target_ip']} for {fix_result['vulnerability_type']}."
                fix_result["ips_suggested_for_blocking"] = suggested_blocks
            else:
                # Success can be true if no blocks are needed and that's the correct outcome
                fix_result["success"] = True # Or False, if suggesting no blocks is considered a failure to find actionable items
                fix_result["message"] = f"No specific IPs suggested for blocking for {fix_result['target_ip']} based on current fixer logic and scan data for {fix_result['vulnerability_type']}."
                
        except json.JSONDecodeError:
            msg = "Error: Invalid JSON data provided to ddos_fixer.py."
            print(f"[ddos_fixer_main] {msg}", file=sys.stderr)
            fix_result["message"] = msg
        except Exception as e:
            msg = f"Error processing DDoS scan data in fixer: {e}"
            print(f"[ddos_fixer_main] {msg} (Data: {sys.argv[1][:200]})", file=sys.stderr) # Log part of data for debug
            fix_result["message"] = msg
    else:
        error_msg = "Error: Missing scan_data_json argument. Usage: python3 ddos_fixer.py '<scan_result_json>'"
        print(f"[ddos_fixer_main] {error_msg}", file=sys.stderr)
        fix_result["message"] = error_msg

    print(json.dumps(fix_result))
