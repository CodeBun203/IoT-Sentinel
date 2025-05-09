import json
import os

class ACLManager:
    def __init__(self):
        """Initialize ACL configuration from file and print its contents."""
        self.file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "acl_config.json")

        try:
            with open(self.file_path, "r") as acl_file:
                self.acl = json.load(acl_file)

                # Debugging: Print the full ACL configuration
                print("\n[ACL] LOADED CONFIGURATION:")
                print(json.dumps(self.acl, indent=4))  # Pretty-print ACL config

                # Validate ACL dictionary structure carefully
                if isinstance(self.acl, dict):
                    if "allowed" in self.acl and "denied" in self.acl:
                        print("[ACL] Successfully loaded ACL rules.")
                    else:
                        print("[ACL WARNING] ACL config is missing 'allowed' or 'denied' keys. Initializing defaults.")
                        self.acl.setdefault("allowed", [])
                        self.acl.setdefault("denied", [])
                else:
                    print("[ACL ERROR] ACL config is invalid! Resetting rules.")
                    self.acl = {"allowed": [], "denied": []}

        except (FileNotFoundError, json.JSONDecodeError):
            print("[ACL ERROR] ACL configuration file missing or corrupt! Initializing default empty rules.")
            self.acl = {"allowed": [], "denied": []}

        print(f"[ACL] Final ACL rule count - Allowed: {len(self.acl['allowed'])}, Denied: {len(self.acl['denied'])}")

    def check_acl(self, ip, port, protocol, direction="destination"):
        """Check if a traffic flow is allowed based on IP, port, and protocol."""
        print(f"\n[ACL] START CHECK: {direction.upper()} -> IP: {ip}, Port: {port}, Protocol: {protocol}")

        acl_list = self.acl.get("allowed", []) if direction == "destination" else self.acl.get("denied", [])
        print(f"[ACL] Total rules checked: {len(acl_list)}")

        match_found = False

        for rule in acl_list:
            print(f"[ACL] Comparing: Rule IP {rule['ip']}, Rule Port {rule['port']}, Rule Protocol {rule['protocol']}")

            if rule["ip"] == "ANY":
                print(f"[ACL DEBUG] Rule IP is 'ANY', applies to any destination.")
            if rule["port"] == "ANY":
                print(f"[ACL DEBUG] Rule Port is 'ANY', applies to any destination port.")

            # If the rule allows "ANY" IP or "ANY" port, accept traffic immediately
            if (rule["ip"] == "ANY" or rule["ip"] == ip) and (rule["port"] == "ANY" or rule["port"] == port) and rule["protocol"] == protocol:
                print(f"[ACL] MATCH FOUND! TRAFFIC ALLOWED: {ip}, Port {port}, Protocol {protocol} (Explicit Allow)")
                match_found = True
                break

        if not match_found:
            print(f"[ACL] NO MATCH FOUND. TRAFFIC DEFAULT DENY: {ip}, Port {port}, Protocol {protocol} (Not Explicitly Allowed)")

        return match_found

    def block_vulnerability(self, ip, port, protocol):
        """Dynamically add a deny rule to block a detected vulnerability."""
        print(f"[ACL UPDATE] Blocking vulnerability: IP {ip}, Port {port}, Protocol {protocol}")

        self.acl["denied"].append({"ip": ip, "port": port, "protocol": protocol})
        self._save_acl_config()

    def add_rule(self, ip, port, protocol, action="allow"):
        """Dynamically add a rule to ACL (allow or deny traffic)."""
        rule_list = "allowed" if action == "allow" else "denied"

        print(f"[ACL UPDATE] Adding {action.upper()} rule: IP {ip}, Port {port}, Protocol {protocol}")
        self.acl[rule_list].append({"ip": ip, "port": port, "protocol": protocol})
        self._save_acl_config()

    def remove_rule(self, ip, port, protocol, action="allow"):
        """Dynamically remove a rule from ACL."""
        rule_list = "allowed" if action == "allow" else "denied"

        print(f"[ACL UPDATE] Removing {action.upper()} rule: IP {ip}, Port {port}, Protocol {protocol}")
        self.acl[rule_list] = [rule for rule in self.acl[rule_list] if rule["ip"] != ip or rule["port"] != port or rule["protocol"] != protocol]
        self._save_acl_config()

    def _save_acl_config(self):
        """Save the updated ACL configuration back to file."""
        try:
            with open(self.file_path, "w") as acl_file:
                json.dump(self.acl, acl_file, indent=4)
            print("[ACL] Configuration updated successfully.")
        except IOError:
            print("[ACL ERROR] Failed to write ACL configuration to file!")

# Example usage for manual testing
if __name__ == "__main__":
    manager = ACLManager()
    print(manager.check_acl("10.0.0.100", 1883, 6, "destination"))  # Expected: True (Allowed via "ANY")
    print(manager.check_acl("10.0.0.100", 56067, 6, "destination"))  # Expected: True (Allowed via "ANY")
    print(manager.check_acl("10.0.0.100", 3306, 6, "destination"))  # Expected: False (Denied)

    # Block a vulnerability
    manager.block_vulnerability("10.0.0.2", 23, 6)
    print(manager.check_acl("10.0.0.2", 23, 6, "destination"))  # Expected: False (Denied due to vulnerability block)
