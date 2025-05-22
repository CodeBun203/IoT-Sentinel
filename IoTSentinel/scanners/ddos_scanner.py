# /home/mininet/IoTSentinel/scanners/ddos_scanner.py
import json
import sys
import time
import random

# Conceptual: In a real system, this might come from a traffic monitoring component (e.g. within POX)
# For simulation, we'll generate some dummy traffic data.
# TARGET_IPS should be the hosts within your Mininet topology that you want to monitor.
TARGET_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.100"]
SIMULATION_DURATION_SECONDS = 10 # How long to "observe" traffic
PACKET_RATE_THRESHOLD_PER_IP = 200 # Packets per SIMULATION_DURATION_SECONDS to trigger alert
SUSPICIOUS_PORT_THRESHOLD = 100 # Packets to a single port to be suspicious

def simulate_and_analyze_traffic():
    """
    Simulates network traffic and analyzes it for potential DoS/DDoS patterns.
    In a real system, this would interface with actual traffic monitoring.
    This function will output JSON lines for POX to process if a DoS is suspected.
    """
    print(f"[ddos_scanner_stderr] Starting simulated traffic analysis for {SIMULATION_DURATION_SECONDS} seconds.", file=sys.stderr)
    
    # {target_ip: {src_ip: count, "total_packets": count, "ports": {port: count}}}
    traffic_stats = {target: {"total_packets": 0, "source_ips": {}, "ports_targeted": {}} for target in TARGET_IPS}
    
    # Simulate packet arrivals
    start_time = time.time()
    while time.time() - start_time < SIMULATION_DURATION_SECONDS:
        target_ip = random.choice(TARGET_IPS)
        # Simulate a mix of normal and potentially attack traffic
        num_packets_this_burst = random.randint(1, 30 if random.random() > 0.1 else 100) # Occasional larger bursts
        
        for _ in range(num_packets_this_burst):
            # Simulate source IP (could be spoofed or a few dominant ones in an attack)
            if random.random() > 0.5: # Simulate some source IP diversity
                source_ip = f"10.0.0.{random.randint(10, 20)}" # Internal "bot"
            else:
                source_ip = f"172.16.{random.randint(1,10)}.{random.randint(1,254)}" # External "bot"
            
            # Simulate port being targeted
            target_port = random.choice([22, 23, 80, 1883, 53, random.randint(1024, 65535)])

            traffic_stats[target_ip]["total_packets"] += 1
            traffic_stats[target_ip]["source_ips"][source_ip] = traffic_stats[target_ip]["source_ips"].get(source_ip, 0) + 1
            traffic_stats[target_ip]["ports_targeted"][target_port] = traffic_stats[target_ip]["ports_targeted"].get(target_port, 0) + 1
        
        time.sleep(0.01) # Brief pause

    vulnerabilities_found = []
    for target_ip, stats in traffic_stats.items():
        print(f"[ddos_scanner_stderr] Analysis for {target_ip}: Total packets={stats['total_packets']}, Unique sources={len(stats['source_ips'])}", file=sys.stderr)
        
        potential_attack_sources = []
        # Check for high packet rate from a single source (more like DoS or a single bot)
        for src_ip, count in stats["source_ips"].items():
            if count > PACKET_RATE_THRESHOLD_PER_IP / 2: # If one source is responsible for a large portion
                potential_attack_sources.append({"ip": src_ip, "count": count})
        
        # Check for high overall packet rate (more like DDoS)
        if stats["total_packets"] > PACKET_RATE_THRESHOLD_PER_IP:
            details_msg = (
                f"Potential DoS/DDoS attack detected on {target_ip}. "
                f"Received {stats['total_packets']} packets in {SIMULATION_DURATION_SECONDS}s. "
                f"Distinct source IPs: {len(stats['source_ips'])}. "
            )
            if potential_attack_sources:
                 details_msg += f"Prominent source(s): {potential_attack_sources}. "

            # Check for specific port being hammered
            suspicious_ports_info = []
            for port, count in stats["ports_targeted"].items():
                if count > SUSPICIOUS_PORT_THRESHOLD:
                    suspicious_ports_info.append({"port": port, "count": count})
            if suspicious_ports_info:
                details_msg += f"Suspiciously high traffic to port(s): {suspicious_ports_info}."


            vuln = {
                "scanner": "ddos_scanner",
                "ip": target_ip,
                "vulnerability": "potential_dos_ddos_attack",
                "details": details_msg,
                "packet_count": stats["total_packets"],
                "source_ip_count": len(stats["source_ips"]),
                "prominent_sources": potential_attack_sources, # Top talkers
                "targeted_ports_info": suspicious_ports_info,
                "severity": "critical" 
            }
            print(json.dumps(vuln)) # Output for POX
            vulnerabilities_found.append(vuln)

    if not vulnerabilities_found:
        print(json.dumps({
            "scanner": "ddos_scanner",
            "status": "scan_complete_no_dos_patterns_detected_in_simulation",
            "targets_checked": TARGET_IPS
        }))
        print("[ddos_scanner_stderr] No significant DoS/DDoS patterns detected in this simulation cycle.", file=sys.stderr)

    print("[ddos_scanner_stderr] ddos_scanner.py simulation finished.", file=sys.stderr)

if __name__ == "__main__":
    simulate_and_analyze_traffic()
