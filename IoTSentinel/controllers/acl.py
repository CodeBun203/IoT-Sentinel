# /home/mininet/IoTSentinel/controllers/acl.py
import json
import os
import sys 

class ACLManager:
    def __init__(self):
        self.file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "acl_config.json") #
        print(f"[ACLManager INFO] Attempting to load ACL config from: {self.file_path}", file=sys.stderr) #
        
        try:
            with open(self.file_path, "r") as acl_file: #
                self.acl = json.load(acl_file) #
                if not isinstance(self.acl, dict) or "allowed" not in self.acl or "denied" not in self.acl: #
                    print("[ACLManager WARNING] ACL config is malformed or missing keys. Initializing defaults.", file=sys.stderr) #
                    self.acl = {"allowed": [], "denied": []} #
                else:
                    print("[ACLManager INFO] Successfully loaded ACL rules.", file=sys.stderr) #
                    print(f"  Loaded 'allowed' rules ({len(self.acl.get('allowed',[]))}): {json.dumps(self.acl.get('allowed',[]))}", file=sys.stderr) #
                    print(f"  Loaded 'denied' rules ({len(self.acl.get('denied',[]))}): {json.dumps(self.acl.get('denied',[]))}", file=sys.stderr) #

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[ACLManager ERROR] ACL configuration file missing or corrupt at {self.file_path}! Error: {e}. Initializing default empty rules.", file=sys.stderr) #
            self.acl = {"allowed": [], "denied": []} #
        except Exception as e:
            print(f"[ACLManager ERROR] Unexpected error loading ACL config: {e}. Initializing defaults.", file=sys.stderr) #
            self.acl = {"allowed": [], "denied": []} #

    def _matches_rule(self, rule, ip_to_check, port, protocol): # Renamed 'ip' to 'ip_to_check'
        rule_ip = rule.get("ip") #
        rule_port = rule.get("port") 
        rule_protocol = rule.get("protocol") 

        ip_matches = (rule_ip == "ANY" or rule_ip == ip_to_check) #

        proto_to_compare_with_rule = protocol #
        rule_proto_for_comparison = rule_protocol #
        if isinstance(rule_protocol, str) and rule_protocol.isdigit(): #
            rule_proto_for_comparison = int(rule_protocol) #
        
        protocol_matches = (rule_protocol == "ANY" or rule_proto_for_comparison == proto_to_compare_with_rule) #

        packet_port_matches = False #
        if rule_port == "ANY": #
            packet_port_matches = True #
        elif isinstance(port, int): 
            if isinstance(rule_port, int) and rule_port == port: #
                packet_port_matches = True #
            elif isinstance(rule_port, str) and rule_port.isdigit() and int(rule_port) == port: #
                packet_port_matches = True #
        
        # match_details = ( # # Removed for brevity
        #     f"    Rule: ip='{rule_ip}', port='{rule_port}', proto='{rule_protocol}' vs " #
        #     f"Packet: ip='{ip_to_check}', port={port}, proto={protocol}. " #
        #     f"Match: ip={ip_matches}, port={packet_port_matches}, proto={protocol_matches}" #
        # ) #
        # print(match_details, file=sys.stderr) #
        return ip_matches and packet_port_matches and protocol_matches

    def check_acl(self, ip_to_check, port, protocol, direction="destination"): # Added direction, ip_to_check
        # The 'direction' parameter is conceptual here unless rules themselves have a direction field.
        # For simplicity, we assume rules are general, and 'ip_to_check' is src or dst IP based on context.
        # A more robust ACL would have rules specifying src_ip, dst_ip, src_port, dst_port.
        # This simplified version checks 'ip_to_check' against the 'ip' field in the rule.
        
        if not isinstance(port, int): #
            try:
                port = int(port) 
            except ValueError:
                print(f"[ACLManager WARNING] Invalid non-integer port value '{port}' during check.", file=sys.stderr) #

        # Check DENY rules first
        for rule in self.acl.get("denied", []): #
            if self._matches_rule(rule, ip_to_check, port, protocol): #
                print(f"[ACLManager MATCH] DENIED by rule: {json.dumps(rule)} for packet (IP_checked: {ip_to_check}, Port: {port}, Proto: {protocol}, Direction: {direction})", file=sys.stderr) #
                return False 

        # Check ALLOW rules if no DENY rule matched
        for rule in self.acl.get("allowed", []): #
            if self._matches_rule(rule, ip_to_check, port, protocol): #
                # print(f"[ACLManager MATCH] ALLOWED by rule: {json.dumps(rule)} for packet (IP_checked: {ip_to_check}, Port: {port}, Proto: {protocol}, Direction: {direction})", file=sys.stderr) #
                return True

        # Default behavior depends on the list: if it was a deny list, default is allow. If allow list, default is deny.
        # For a unified check_acl: If no DENY rule matched, and no ALLOW rule explicitly matched, what to do?
        # Current logic: default deny if no explicit allow.
        print(f"[ACLManager MATCH] DEFAULT DENY (no matching allow/deny rule) for packet (IP_checked: {ip_to_check}, Port: {port}, Proto: {protocol}, Direction: {direction})", file=sys.stderr) #
        return False 

    def add_rule(self, ip, port, protocol, action="allow"): #
        rule_list_name = "allowed" if action == "allow" else "denied" #
        
        if rule_list_name not in self.acl: #
            self.acl[rule_list_name] = [] #

        new_rule_port = port #
        if isinstance(port, str) and port.isdigit(): #
            new_rule_port = int(port) #

        new_rule = {"ip": ip, "port": new_rule_port, "protocol": int(protocol) if isinstance(protocol, str) and protocol.isdigit() else protocol} #

        if new_rule not in self.acl[rule_list_name]: #
            self.acl[rule_list_name].append(new_rule) #
            print(f"[ACLManager UPDATE] Added {action.upper()} rule: {json.dumps(new_rule)}", file=sys.stderr) #
            self._save_acl_config() #
        else:
            print(f"[ACLManager UPDATE] Rule {json.dumps(new_rule)} already exists in {action.upper()} list.", file=sys.stderr) #

    def remove_rule(self, ip, port, protocol, action="allow"): #
        rule_list_name = "allowed" if action == "allow" else "denied" #
        
        if rule_list_name not in self.acl: return #

        rule_port_to_remove = port #
        if isinstance(port, str) and port.isdigit(): #
            rule_port_to_remove = int(port) #
        
        rule_to_remove = {"ip": ip, "port": rule_port_to_remove, "protocol": int(protocol) if isinstance(protocol, str) and protocol.isdigit() else protocol} #
        
        if rule_to_remove in self.acl[rule_list_name]: #
            self.acl[rule_list_name].remove(rule_to_remove) #
            print(f"[ACLManager UPDATE] Removed {action.upper()} rule: {json.dumps(rule_to_remove)}", file=sys.stderr) #
            self._save_acl_config() #
        else:
            print(f"[ACLManager UPDATE] Rule {json.dumps(rule_to_remove)} not found in {action.upper()} list for removal.", file=sys.stderr) #

    def _save_acl_config(self): #
        try:
            with open(self.file_path, "w") as acl_file: #
                json.dump(self.acl, acl_file, indent=4) #
            print(f"[ACLManager INFO] Configuration saved successfully to {self.file_path}.", file=sys.stderr) #
        except IOError:
            print(f"[ACLManager ERROR] Failed to write ACL configuration to {self.file_path}!", file=sys.stderr) #
