import os
import json

class ForwardingTableManager:
    def __init__(self):
        self.file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "forwarding_table.json")
        try:
            with open(self.file_path, "r") as table_file:
                self.forwarding_table = json.load(table_file)
                if not isinstance(self.forwarding_table, dict):
                    print("Invalid forwarding table format. Initializing empty table.")
                    self.forwarding_table = {}
        except (FileNotFoundError, json.JSONDecodeError):
            print("Forwarding table file not found or corrupted. Initializing with default values.")
            self.forwarding_table = {}

    def get_next_hop(self, ip):
        """Get the next hop for a given IP address."""
        return self.forwarding_table.get(ip, None)

    def update_table(self, ip, next_hop, port):
        """Update the forwarding table dynamically."""
        self.forwarding_table[ip] = {"next_hop": next_hop, "port": port}

        with open(self.file_path, "w") as table_file:
            json.dump(self.forwarding_table, table_file, indent=4)

# Example usage
if __name__ == "__main__":
    manager = ForwardingTableManager()
    print(manager.get_next_hop("10.0.0.1"))
    manager.update_table("10.0.0.2", "s1", 2)
