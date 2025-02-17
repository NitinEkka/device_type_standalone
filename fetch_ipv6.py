import subprocess
import re

def get_ipv6_interfaces():
    """Retrieve all active IPv6 interfaces (excluding loopback), including link-local addresses."""
    interfaces = {}
    cmd = ["ip", "-6", "addr", "show", "up"]
    print(f"[*] Executing: {' '.join(cmd)}") 
    result = subprocess.run(cmd, capture_output=True, text=True)
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

    cmd = ["ping6", "-c", "3", "-I", interface, "ff02::1"]
    print(f"[*] Executing: {' '.join(cmd)}")  # Print command
    result = subprocess.run(cmd, capture_output=True, text=True)
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
    """Run nmap scan on discovered IPv6 hosts and return list of dictionaries."""
    if not hosts:
        print("[!] No hosts to scan.")
        return []
    
    print(f"[*] Running Nmap on {len(hosts)} hosts...")
    cmd = ["nmap", "-6", "-sn", "-e", interface] + hosts
    print(f"[*] Executing: {' '.join(cmd)}")  # Print command
    result = subprocess.run(cmd, capture_output=True, text=True)

    hosts_data = []
    ipv6, mac = None, None

    for line in result.stdout.split("\n"):
        if "Nmap scan report for" in line:
            ipv6 = line.split()[-1]
        elif "MAC Address:" in line:
            mac = line.split()[2]
            if ipv6 and mac:
                hosts_data.append({"mac": mac, "ipv6": ipv6})
                ipv6, mac = None, None  # Reset for next host

    print("[+] Nmap scan results:")
    print(hosts_data)

    return hosts_data

if __name__ == "__main__":
    interfaces = get_ipv6_interfaces()
    print(f"Available IPv6 Interfaces: {interfaces}")

    interface_host_map = {}
    
    for interface, ipv6_address in interfaces.items():
        live_hosts = discover_hosts(interface, ipv6_address)
        scanned_hosts = run_nmap(interface, live_hosts)
        if scanned_hosts:
            interface_host_map[interface] = scanned_hosts
    
    print("\nFinal Interface-Hosts Mapping:")
    print(interface_host_map)
