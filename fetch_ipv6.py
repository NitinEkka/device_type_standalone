import subprocess
import re

def get_ipv6_interfaces():
    """Retrieve all active IPv6 interfaces (excluding loopback), including link-local addresses."""
    interfaces = {}
    result = subprocess.run(["ip", "-6", "addr", "show", "up"], capture_output=True, text=True)
    lines = result.stdout.split("\n")

    current_iface = None
    for line in lines:
        if line.startswith(" "):  # This line contains an IPv6 address
            match = re.search(r"inet6 ([a-fA-F0-9:]+)/(\d+)", line)
            if match:
                ip_addr, prefix = match.groups()
                if ip_addr.startswith("fe80::"):  # If it's link-local, add interface scope
                    ip_addr += f"%{current_iface}"  # Append scope identifier (interface)
                interfaces[current_iface] = ip_addr
        else:  # This line contains an interface name
            match = re.search(r"^\d+: ([^:]+):", line)
            if match:
                current_iface = match.group(1)

    # Exclude loopback interface "lo"
    interfaces = {k: v for k, v in interfaces.items() if k and k != "lo"}
    
    return interfaces

def discover_hosts(interface, ipv6_subnet):
    """Discover live hosts on the given interface using ping6."""
    print(f"[*] Discovering hosts on interface: {interface}...")

    # Use ping6 to find live hosts
    result = subprocess.run(["ping6", "-c", "3", "-I", interface, "ff02::1"], capture_output=True, text=True)
    lines = result.stdout.split("\n")
    
    live_hosts = []
    for line in lines:
        match = re.search(r"from ([a-fA-F0-9:]+)%", line)  # Extract IPv6 addresses
        if match:
            ip = match.group(1)
            if ip not in live_hosts:
                live_hosts.append(ip)

    if not live_hosts:
        print(f"[!] No live hosts found on {interface}")
    else:
        print(f"[+] Live hosts found: {live_hosts}")
    
    return live_hosts

def run_nmap(interface, hosts):
    """Run nmap scan on discovered IPv6 hosts."""
    if not hosts:
        print("[!] No hosts to scan.")
        return
    
    print(f"[*] Running Nmap on {len(hosts)} hosts...")
    cmd = ["nmap", "-6", "-sn", "-e", interface] + hosts
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print("[+] Nmap scan results:\n")
    print(result.stdout)

if __name__ == "__main__":
    interfaces = get_ipv6_interfaces()
    print(f"Available IPv6 Interfaces: {interfaces}")

    for interface, ipv6_address in interfaces.items():
        live_hosts = discover_hosts(interface, ipv6_address)
        run_nmap(interface, live_hosts)
