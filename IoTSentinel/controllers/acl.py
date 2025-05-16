# In IoTSentinel/controllers/acl.py

import json
import os

class ACLManager:
    def __init__(self):
        self.file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "acl_config.json")
        try:
            with open(self.file_path, "r") as acl_file:
                self.acl = json.load(acl_file)
                if not isinstance(self.acl, dict) or "allowed" not in self.acl or "denied" not in self.acl:
                    print("[ACL WARNING] ACL config is malformed or missing keys. Initializing defaults.")
                    self.acl = {"allowed": [], "denied": []}
                else:
                    print("[ACL] Successfully loaded ACL rules.")
        except (FileNotFoundError, json.JSONDecodeError):
            print("[ACL ERROR] ACL configuration file missing or corrupt! Initializing default empty rules.")
            self.acl = {"allowed": [], "denied": []}
        # print(f"[ACL] Initial - Allowed: {len(self.acl.get('allowed',[]))}, Denied: {len(self.acl.get('denied',[]))}")
        # print(json.dumps(self.acl, indent=4))


    def _matches_rule(self, rule, ip, port, protocol):
        """Helper function to check if a packet matches a specific ACL rule."""
        # Ensure port matching is done carefully, especially with "ANY"
        rule_port = rule.get("port")
        packet_port_matches = False
        if rule_port == "ANY" or rule_port == port:
            packet_port_matches = True
        elif isinstance(rule_port, (int, str)) and isinstance(port, (int, str)):
            try:
                if int(rule_port) == int(port):
                    packet_port_matches = True
            except ValueError: # If port cannot be converted to int (e.g. it's "ANY" but wasn't caught)
                pass


        ip_matches = (rule.get("ip") == "ANY" or rule.get("ip") == ip)
        protocol_matches = (rule.get("protocol") == "ANY" or rule.get("protocol") == protocol)

        return ip_matches and packet_port_matches and protocol_matches

    def check_acl(self, ip, port, protocol, direction="destination"): # Direction not really used here anymore
        """
        Checks if traffic is permitted based on ACL rules.
        1. Checks DENY rules. If match, traffic is DENIED (returns False).
        2. Checks ALLOW rules. If match, traffic is ALLOWED (returns True).
        3. Default: If no match in DENY or ALLOW, traffic is DENIED (returns False).
        """
        # Ensure port is an integer for comparison if it's not "ANY"
        # The port from tcp_packet.dstport will be an int. acl_config.json uses strings or ints.
        if port != "ANY":
            try:
                port = int(port)
            except ValueError:
                print(f"[ACL WARNING] Invalid port value '{port}' during check. Treating as non-match unless rule port is 'ANY'.")
                # This case should ideally not happen if inputs are clean

        # Check DENY rules first
        for rule in self.acl.get("denied", []):
            if self._matches_rule(rule, ip, port, protocol):
                print(f"[ACL] DENIED by rule: {rule} for {ip}:{port} (Proto: {protocol})")
                return False # Deny traffic

        # Check ALLOW rules if no DENY rule matched
        for rule in self.acl.get("allowed", []):
            if self._matches_rule(rule, ip, port, protocol):
                print(f"[ACL] ALLOWED by rule: {rule} for {ip}:{port} (Proto: {protocol})")
                return True # Allow traffic

        print(f"[ACL] DEFAULT DENY (no matching allow/deny rule) for {ip}:{port} (Proto: {protocol})")
        return False # Default deny if no rule explicitly allows

    def add_rule(self, ip, port, protocol, action="allow"):
        """Dynamically add a rule to ACL (allow or deny traffic)."""
        rule_list_name = "allowed" if action == "allow" else "denied"
        
        # Ensure the list exists
        if rule_list_name not in self.acl:
            self.acl[rule_list_name] = []

        new_rule = {"ip": ip, "port": port, "protocol": protocol}

        # Avoid duplicate rules
        if new_rule not in self.acl[rule_list_name]:
            self.acl[rule_list_name].append(new_rule)
            print(f"[ACL UPDATE] Added {action.upper()} rule: {new_rule}")
            self._save_acl_config()
        else:
            print(f"[ACL UPDATE] Rule {new_rule} already exists in {action.upper()} list.")


    def remove_rule(self, ip, port, protocol, action="allow"):
        """Dynamically remove a rule from ACL."""
        rule_list_name = "allowed" if action == "allow" else "denied"
        
        if rule_list_name not in self.acl:
            return # Nothing to remove

        rule_to_remove = {"ip": ip, "port": port, "protocol": protocol}
        
        if rule_to_remove in self.acl[rule_list_name]:
            self.acl[rule_list_name].remove(rule_to_remove)
            print(f"[ACL UPDATE] Removed {action.upper()} rule: {rule_to_remove}")
            self._save_acl_config()
        else:
            print(f"[ACL UPDATE] Rule {rule_to_remove} not found in {action.upper()} list for removal.")

    def _save_acl_config(self):
        """Save the updated ACL configuration back to file."""
        try:
            with open(self.file_path, "w") as acl_file:
                json.dump(self.acl, acl_file, indent=4)
            # print("[ACL] Configuration saved successfully.")
        except IOError:
            print("[ACL ERROR] Failed to write ACL configuration to file!")

# Example usage for manual testing
if __name__ == "__main__":
    manager = ACLManager()
    # Test cases should reflect the new logic: deny first, then allow, then default deny.
    # Initial acl_config.json should have a default allow ANY/ANY/6 for testing,
    # or specific allows for MQTT, etc.
    # Example: Deny telnet to 10.0.0.2
    # manager.add_rule("10.0.0.2", 23, 6, "deny")
    # print(f"Check 10.0.0.2:23 (TCP) (Telnet): Expected False -> {manager.check_acl('10.0.0.2', 23, 6)}")
    # print(f"Check 10.0.0.2:80 (TCP) (HTTP): Expected True (if allowed by ANY rule) -> {manager.check_acl('10.0.0.2', 80, 6)}")
    # print(f"Check 10.0.0.100:1883 (TCP) (MQTT): Expected True (if allowed) -> {manager.check_acl('10.0.0.100', 1883, 6)}")
