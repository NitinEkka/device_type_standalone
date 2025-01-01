import telnetlib
from netmiko import ConnectHandler
import re
from .base import APBase
import pandas as pd
import time
from log_helper import log_message

class CiscoAP(APBase):
    def connect(self):
        """Connect to the Cisco AP via SSH or Telnet."""
        if self.protocol == 'ssh':
            self.connection = ConnectHandler(
                device_type='cisco_ios',
                ip=self.ip,
                username=self.username,
                password=self.password,
                port=self.port
            )
        elif self.protocol == 'telnet':
            self.connection = telnetlib.Telnet(self.ip, self.port)
            self.connection.read_until(b"Username: ")
            self.connection.write(self.username.encode('ascii') + b"\n")
            self.connection.read_until(b"Password: ")
            self.connection.write(self.password.encode('ascii') + b"\n")
        else:
            raise ValueError("Unsupported protocol: use 'ssh' or 'telnet'")

    def get_configured_ssid(self):
        # Handle SSH or Telnet protocol
        if self.protocol == 'ssh':
            output = self.connection.send_command("show dot11 associations")
        elif self.protocol == 'telnet':
            # Send the command via Telnet
            self.connection.write(b"show dot11 associations\n")
            raw_output = ''
            meaningful_output = ''
            while True:
                # Read a chunk of data
                chunk = self.connection.read_very_eager().decode('ascii')
                raw_output += chunk
                if chunk:
                    log_message("INFO","scanner_tool","CHUNK RECEIVED: ", chunk.strip())
                
                # Check for and ignore single-character chunks and 'ap>' prompt
                if re.search(r"^ap>$", chunk.strip()):  # Detect 'ap>' specifically
                    log_message("INFO","scanner_tool","Detected prompt 'ap>'. Continuing to next chunk.")
                    continue
                
                # Ignore chunks that are too small to be meaningful
                if len(chunk.strip()) <= 5:
                    continue
                
                # Accumulate meaningful output
                meaningful_output += chunk
                
                # Check for the end prompt 'ap>' indicating completion
                if re.search(r"ap>$", raw_output.strip()):
                    break
                
                # Handle pagination
                if "--More--" in chunk or "---- More ----" in chunk:
                    self.connection.write(b" ")

            output = meaningful_output.strip()

        # Parse the AP details and construct the payload
        host_payload = self.parse_ap_details(output, ap_mac)
        for host in host_payload:
            host['bssid'] = host['ssid']
            host['security_type'] = ""
            del host['name'] 
        return host_payload

    def get_discovered_ssid(self):

        host_payload = [{}]
        
        return host_payload

    def getSSID(self):
        """Fetch SSIDs from Cisco AP."""
        if self.protocol == 'ssh':
            output = self.connection.send_command("show wlan summary")
        elif self.protocol == 'telnet':
            self.connection.write(b"show wlan summary\n")
            output = self.connection.read_until(b"#").decode('ascii')
        
        # Parse output to extract SSIDs (this part depends on the actual output format)
        ssids = self._parse_ssid_output(output)
        ssids = [('ssid1', 'ssid2', 'ssid3', 'ssid4')]
        return ssids

    def _parse_ssid_output(self, output):
        """Helper function to parse SSID from command output."""
        ssids = []
        for line in output.splitlines():
            if "SSID" in line:
                ssid = line.split()[1]  # Adjust based on actual output format
                ssids.append(ssid)
        return ssids

    def gethosts(self, SSID):
        """Fetch connected hosts for a specific SSID using regex."""
        if self.protocol == 'ssh':
            output = self.connection.send_command(f"show dot11 associations {SSID}")
        elif self.protocol == 'telnet':
            self.connection.write(f"show dot11 associations {SSID}\n".encode('ascii'))
            output = self.connection.read_until(b"#").decode('ascii')
        sample_data = [
                {'mac_address' : 'mac1', 'ip_address' : 'ip1', 'supportedBand' : ['2.4G', '5G'], 'controllerId' : 'ac_mac'}
                ]
        # Parse output to get hosts for the given SSID
        # return self._parse_hosts_output(output)
        return sample_data 

    def getallHosts(self, SSID_LIST):
        """Fetch connected hosts for all SSIDs using regex."""
        hosts_all = [{
            'ssid1' : [{{'mac_address' : 'mac1', 'ip_address' : 'ip1'},{'mac_address' : 'mac2', 'ip_address' : 'ip2'}}],
            'ssid2' : [{{'mac_address' : 'mac1', 'ip_address' : 'ip1'},{'mac_address' : 'mac2', 'ip_address' : 'ip2'}}]
        }]
        # for SSID in SSID_LIST:
        #     hosts_all.extend(self.gethosts(SSID))
        return hosts_all

    def _parse_hosts_output(self, output):
        """Helper function to parse hosts from command output using regex."""
        hosts = []
        
        # Regex pattern to match MAC and IP addresses (adjust based on actual format)
        mac_ip_regex = re.compile(r"(\w{4}\.\w{4}\.\w{4})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

        for line in output.splitlines():
            match = mac_ip_regex.search(line)
            if match:
                mac_address = match.group(1)
                ip_address = match.group(2)
                hosts.append({"mac_address": mac_address, "ip_address": ip_address})

        return hosts

    def parse_ap_details(self, output):
        parsed_hosts = []

        # Split the output into lines for processing
        lines = output.strip().split("\n")

        # Initialize flags and placeholders
        current_ssid = None
        parsing_devices = False

        for line in lines:
            # Check for SSID line
            if line.startswith("SSID ["):
                match = re.search(r"SSID \[([^\]]+)\]", line)
                if match:
                    current_ssid = match.group(1)  # Update the current SSID
                parsing_devices = False  # Reset device parsing when a new SSID is encountered
                continue

            # Check for the start of the device table
            if line.startswith("MAC Address"):
                parsing_devices = True
                continue

            # Parse device details if within the device table
            if parsing_devices:
                match = re.match(
                    r"(?P<mac>\S+)\s+(?P<ip>\S+)\s+(?P<ipv6>[^\s]+)\s+(?P<device>\S+)\s+(?P<name>\S+)\s+(?P<parent>\S+)\s+(?P<state>\S+)",
                    line
                )
                if match:
                    device_info = match.groupdict()
                    parsed_hosts.append({
                        "ap_mac": device_info["mac"],
                        "host_mac": device_info["mac"],
                        "ssid": current_ssid or "",  
                        "host_ip": device_info["ip"],
                        "name": device_info["name"],
                    })

        return parsed_hosts

    

    def getAps(self):
        # Handle SSH or Telnet protocol
        if self.protocol == 'ssh':
            output = self.connection.send_command("show dot11 associations")
        elif self.protocol == 'telnet':
            # Send the command via Telnet
            self.connection.write(b"show dot11 associations\n")
            raw_output = ''
            meaningful_output = ''
            while True:
                # Read a chunk of data
                chunk = self.connection.read_very_eager().decode('ascii')
                raw_output += chunk
                if chunk:
                    log_message("INFO","scanner_tool",f"CHUNK RECEIVED: {chunk.strip()}")
                
                # Check for and ignore single-character chunks and 'ap>' prompt
                if re.search(r"^ap>$", chunk.strip()):  # Detect 'ap>' specifically
                    continue
                
                # Ignore chunks that are too small to be meaningful
                if len(chunk.strip()) <= 5:
                    continue
                
                # Accumulate meaningful output
                meaningful_output += chunk
                
                # Check for the end prompt 'ap>' indicating completion
                if re.search(r"ap>$", raw_output.strip()):
                    break
                
                # Handle pagination
                if "--More--" in chunk or "---- More ----" in chunk:
                    self.connection.write(b" ")

            output = meaningful_output.strip()

        # Parse the AP details and construct the payload
        host_payload = self.parse_ap_details(output)
        return host_payload

