# /home/mininet/IoTSentinel/controllers/acl.py

import json
import os
import sys # For stderr

class ACLManager:
    def __init__(self):
        # This path should resolve to IoTSentinel/controllers/acl_config.json
        self.file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "acl_config.json")
        print(f"[ACLManager INFO] Attempting to load ACL config from: {self.file_path}", file=sys.stderr)
        
        try:
            with open(self.file_path, "r") as acl_file:
                self.acl = json.load(acl_file)
                if not isinstance(self.acl, dict) or "allowed" not in self.acl or "denied" not in self.acl:
                    print("[ACLManager WARNING] ACL config is malformed or missing keys. Initializing defaults.", file=sys.stderr)
                    self.acl = {"allowed": [], "denied": []}
                else:
                    print("[ACLManager INFO] Successfully loaded ACL rules.", file=sys.stderr)
                    # Detailed logging of loaded rules
                    print(f"  Loaded 'allowed' rules ({len(self.acl.get('allowed',[]))}): {json.dumps(self.acl.get('allowed',[]))}", file=sys.stderr)
                    print(f"  Loaded 'denied' rules ({len(self.acl.get('denied',[]))}): {json.dumps(self.acl.get('denied',[]))}", file=sys.stderr)

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[ACLManager ERROR] ACL configuration file missing or corrupt at {self.file_path}! Error: {e}. Initializing default empty rules.", file=sys.stderr)
            self.acl = {"allowed": [], "denied": []}
        except Exception as e:
            print(f"[ACLManager ERROR] Unexpected error loading ACL config: {e}. Initializing defaults.", file=sys.stderr)
            self.acl = {"allowed": [], "denied": []}


    def _matches_rule(self, rule, ip, port, protocol):
        rule_ip = rule.get("ip")
        rule_port = rule.get("port") # This can be "ANY" (string) or an int/string number
        rule_protocol = rule.get("protocol") # This can be "ANY" (string) or an int

        # IP Match
        ip_matches = (rule_ip == "ANY" or rule_ip == ip)

        # Protocol Match
        # Ensure rule_protocol is treated as int if it's numeric string, for comparison with int protocol
        proto_to_compare_with_rule = protocol
        rule_proto_for_comparison = rule_protocol
        if isinstance(rule_protocol, str) and rule_protocol.isdigit():
            rule_proto_for_comparison = int(rule_protocol)
        
        protocol_matches = (rule_protocol == "ANY" or rule_proto_for_comparison == proto_to_compare_with_rule)

        # Port Match
        # The 'port' argument to this function (from packet) should be an integer.
        # The rule_port can be "ANY" (string) or an int/string number.
        packet_port_matches = False
        if rule_port == "ANY":
            packet_port_matches = True
        elif isinstance(port, int): # Packet port is an int
            if isinstance(rule_port, int) and rule_port == port:
                packet_port_matches = True
            elif isinstance(rule_port, str) and rule_port.isdigit() and int(rule_port) == port:
                packet_port_matches = True
        # Add case for when packet port is 0 (e.g. ICMP, where rule might specify specific port for other reasons)
        # but generally for ICMP, rule_port would be "ANY" or a type/code if your rules are that granular.

        match_details = (
            f"    Rule: ip='{rule_ip}', port='{rule_port}', proto='{rule_protocol}' vs "
            f"Packet: ip='{ip}', port={port}, proto={protocol}. "
            f"Match: ip={ip_matches}, port={packet_port_matches}, proto={protocol_matches}"
        )
        # print(match_details, file=sys.stderr) # Can be very verbose
        return ip_matches and packet_port_matches and protocol_matches

    def check_acl(self, ip, port, protocol, direction="destination"):
        # Ensure port is an integer for comparison if it's not "ANY" (should already be from POX)
        if not isinstance(port, int):
            try:
                port = int(port) # Should typically be an int already from packet processing
            except ValueError:
                # This case implies port was something like "ANY" or non-numeric string from caller
                # which shouldn't happen if 'port' is from a parsed packet's dstport.
                # For ICMP etc., it's often passed as 0.
                print(f"[ACLManager WARNING] Invalid non-integer port value '{port}' during check. This is unexpected.", file=sys.stderr)

        # Check DENY rules first
        for rule in self.acl.get("denied", []):
            if self._matches_rule(rule, ip, port, protocol):
                # ACL_MATCH_LOG: Deny
                print(f"[ACLManager MATCH] DENIED by rule: {json.dumps(rule)} for packet (IP: {ip}, Port: {port}, Proto: {protocol})", file=sys.stderr)
                return False 

        # Check ALLOW rules if no DENY rule matched
        for rule in self.acl.get("allowed", []):
            if self._matches_rule(rule, ip, port, protocol):
                # ACL_MATCH_LOG: Allow
                # print(f"[ACLManager MATCH] ALLOWED by rule: {json.dumps(rule)} for packet (IP: {ip}, Port: {port}, Proto: {protocol})", file=sys.stderr)
                return True

        # ACL_MATCH_LOG: Default Deny
        print(f"[ACLManager MATCH] DEFAULT DENY (no matching allow/deny rule) for packet (IP: {ip}, Port: {port}, Proto: {protocol})", file=sys.stderr)
        return False # Default deny if no rule explicitly allows

    def add_rule(self, ip, port, protocol, action="allow"):
        rule_list_name = "allowed" if action == "allow" else "denied"
        
        if rule_list_name not in self.acl:
            self.acl[rule_list_name] = []

        # Ensure port is int if it's a number, or "ANY"
        new_rule_port = port
        if isinstance(port, str) and port.isdigit():
            new_rule_port = int(port)

        new_rule = {"ip": ip, "port": new_rule_port, "protocol": int(protocol) if isinstance(protocol, str) and protocol.isdigit() else protocol}

        if new_rule not in self.acl[rule_list_name]:
            self.acl[rule_list_name].append(new_rule)
            print(f"[ACLManager UPDATE] Added {action.upper()} rule: {json.dumps(new_rule)}", file=sys.stderr)
            self._save_acl_config()
        else:
            print(f"[ACLManager UPDATE] Rule {json.dumps(new_rule)} already exists in {action.upper()} list.", file=sys.stderr)

    def remove_rule(self, ip, port, protocol, action="allow"):
        rule_list_name = "allowed" if action == "allow" else "denied"
        
        if rule_list_name not in self.acl: return

        rule_port_to_remove = port
        if isinstance(port, str) and port.isdigit():
            rule_port_to_remove = int(port)
        
        rule_to_remove = {"ip": ip, "port": rule_port_to_remove, "protocol": int(protocol) if isinstance(protocol, str) and protocol.isdigit() else protocol}
        
        if rule_to_remove in self.acl[rule_list_name]:
            self.acl[rule_list_name].remove(rule_to_remove)
            print(f"[ACLManager UPDATE] Removed {action.upper()} rule: {json.dumps(rule_to_remove)}", file=sys.stderr)
            self._save_acl_config()
        else:
            print(f"[ACLManager UPDATE] Rule {json.dumps(rule_to_remove)} not found in {action.upper()} list for removal.", file=sys.stderr)

    def _save_acl_config(self):
        try:
            with open(self.file_path, "w") as acl_file:
                json.dump(self.acl, acl_file, indent=4)
            print(f"[ACLManager INFO] Configuration saved successfully to {self.file_path}.", file=sys.stderr)
        except IOError:
            print(f"[ACLManager ERROR] Failed to write ACL configuration to {self.file_path}!", file=sys.stderr)
