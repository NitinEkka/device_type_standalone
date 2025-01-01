import subprocess
import json
import nmap

def scanner(host,arguments):
    try:
        all_scanned_hosts = []
        packet = nmap.PortScanner()
        packet.scan(hosts=host,arguments=arguments)
        print(packet)
        for scanned_host in packet.all_hosts():
                print(scanned_host)
                all_scanned_hosts.append(packet[scanned_host])
        return all_scanned_hosts
    except Exception as e:
        print("NMAP EXP", str(e))

def run_nmap_scan(network_range, iface):
    try:
        # Command to run nmap with the provided network range and output as JSON
        namp_arg = f"-e {iface} -sn -PR -PE"
        scanned_hosts = scanner(network_range, namp_arg)
        return scanned_hosts

    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def main():
    # Ask for network range input from the user
    network_range = input("Enter network range (e.g., 192.168.1.0/24 or 10.0.0.0/24): ")
    iface = input("Enter interface (e.g eno1): ")
    # Run the nmap scan
    scan_results = run_nmap_scan(network_range, iface)

    if scan_results:
        # Print formatted JSON output
        print(json.dumps(scan_results, indent=4))
    else:
        print("Failed to run the nmap scan or no results found.")

if __name__ == "__main__":
    main()

