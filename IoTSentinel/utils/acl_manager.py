import os

def add_acl_rule(device_ip, rule):
    """
    Adds an Access Control List (ACL) rule to an IoT device.
    Args:
        device_ip (str): IP address of the device.
        rule (str): ACL rule to apply (e.g., "deny all").
    Returns:
        bool: True if the rule was successfully applied, False otherwise.
    """
    print(f"Adding ACL rule to {device_ip}: {rule}")
    try:
        # Simulate applying the ACL rule (replace with real implementation)
        command = f"apply-acl {rule}"  # Example command for the device
        print(f"Command sent to {device_ip}: {command}")
        return True  # Simulate success
    except Exception as e:
        print(f"Failed to add ACL rule to {device_ip}: {e}")
        return False

def remove_acl_rule(device_ip, rule):
    """
    Removes an Access Control List (ACL) rule from an IoT device.
    Args:
        device_ip (str): IP address of the device.
        rule (str): ACL rule to remove.
    Returns:
        bool: True if the rule was successfully removed, False otherwise.
    """
    print(f"Removing ACL rule from {device_ip}: {rule}")
    try:
        # Simulate removing the ACL rule (replace with real implementation)
        command = f"remove-acl {rule}"  # Example command for the device
        print(f"Command sent to {device_ip}: {command}")
        return True  # Simulate success
    except Exception as e:
        print(f"Failed to remove ACL rule from {device_ip}: {e}")
        return False

if __name__ == "__main__":
    # Example usage
    device_ip = "10.0.0.1"
    acl_rule = "deny all"

    # Add ACL rule
    success = add_acl_rule(device_ip, acl_rule)
    if success:
        print(f"ACL rule applied: {acl_rule}")

    # Remove ACL rule
    success = remove_acl_rule(device_ip, acl_rule)
    if success:
        print(f"ACL rule removed: {acl_rule}")
