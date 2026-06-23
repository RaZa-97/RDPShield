"""
RDPShield Firewall Module
=========================
Blocks and unblocks attacker IPs using Windows Firewall (netsh).

How it works:
- When an attack is detected, this module creates an inbound firewall rule
  that blocks ALL traffic from the attacker's IP address.
- Each rule is named "RDPShield_Block_{ip}" so we can find and remove them.
- The module checks the whitelist before blocking to prevent lockouts.

Requirements:
- Must run as Administrator (netsh needs elevated privileges)
"""

import ipaddress
import subprocess
from config import WHITELIST_IPS, AUTO_BLOCK_ENABLED
from database import log_blocked_ip, unblock_ip_record, is_ip_blocked


def _valid_ip(ip_address):
    """True only for a well-formed single IPv4/IPv6 address. Used to reject
    anything that isn't a plain IP before it reaches a subprocess call."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except (ValueError, TypeError):
        return False


def block_ip(ip_address, reason="RDPShield auto-block"):
    """
    Block an IP address using Windows Firewall.

    What it does:
    - Runs a netsh command to create a firewall rule blocking all inbound
      traffic from the specified IP.
    - The rule name includes the IP so we can identify and remove it later.

    Args:
        ip_address: The attacker's IP to block (e.g., "10.0.100.10")
        reason: Why this IP was blocked (stored in database)

    Returns:
        True if blocked successfully, False otherwise
    """
    # Safety check: reject anything that isn't a plain IP address. This is the
    # value that goes into the netsh command, so it must be strictly validated.
    if not _valid_ip(ip_address):
        print(f"[FIREWALL] REJECTED: '{ip_address}' is not a valid IP address.")
        return False

    # Safety check: don't block whitelisted IPs
    if ip_address in WHITELIST_IPS:
        print(f"[FIREWALL] SKIPPED: {ip_address} is whitelisted.")
        return False

    # Safety check: is auto-block enabled?
    if not AUTO_BLOCK_ENABLED:
        print(f"[FIREWALL] Auto-block disabled. Would have blocked {ip_address}")
        return False

    # Safety check: is this IP already blocked?
    if is_ip_blocked(ip_address):
        print(f"[FIREWALL] {ip_address} is already blocked.")
        return False

    # Create the firewall rule name
    rule_name = f"RDPShield_Block_{ip_address}"

    # Build the netsh command as an argument list (shell=False) so the IP can
    # never be interpreted as shell syntax. Creates an inbound rule blocking
    # ALL traffic from this IP.
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes",
    ]

    try:
        # Run the command
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # Success - record in database
            log_blocked_ip(ip_address, reason)
            print(f"[FIREWALL] BLOCKED: {ip_address} (Reason: {reason})")
            return True
        else:
            print(f"[FIREWALL] ERROR blocking {ip_address}: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print(f"[FIREWALL] TIMEOUT blocking {ip_address}")
        return False
    except Exception as e:
        print(f"[FIREWALL] EXCEPTION blocking {ip_address}: {e}")
        return False


def unblock_ip(ip_address):
    """
    Remove the firewall block for an IP address.

    What it does:
    - Deletes the netsh firewall rule for this IP.
    - Updates the database to mark the IP as unblocked.

    Args:
        ip_address: The IP to unblock

    Returns:
        True if unblocked successfully, False otherwise
    """
    if not _valid_ip(ip_address):
        print(f"[FIREWALL] REJECTED: '{ip_address}' is not a valid IP address.")
        return False

    rule_name = f"RDPShield_Block_{ip_address}"

    cmd = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]

    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            unblock_ip_record(ip_address)
            print(f"[FIREWALL] UNBLOCKED: {ip_address}")
            return True
        else:
            print(f"[FIREWALL] ERROR unblocking {ip_address}: {result.stderr}")
            return False

    except Exception as e:
        print(f"[FIREWALL] EXCEPTION unblocking {ip_address}: {e}")
        return False


def list_rdpshield_rules():
    """
    List all firewall rules created by RDPShield.
    Useful for debugging and the dashboard.

    Returns:
        List of rule names that start with "RDPShield_Block_"
    """
    cmd = 'netsh advfirewall firewall show rule name=all dir=in'

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )

        rules = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Rule Name:") and "RDPShield_Block_" in line:
                rule_name = line.replace("Rule Name:", "").strip()
                rules.append(rule_name)

        return rules

    except Exception as e:
        print(f"[FIREWALL] Error listing rules: {e}")
        return []


# If run directly, show current RDPShield firewall rules
if __name__ == "__main__":
    print("[FIREWALL] Current RDPShield blocking rules:")
    rules = list_rdpshield_rules()
    if rules:
        for r in rules:
            print(f"  - {r}")
    else:
        print("  (none)")
