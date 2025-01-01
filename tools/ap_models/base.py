class APBase:
    def __init__(self, model, username, password, ip, port, protocol):
        self.model = model
        self.username = username
        self.password = password
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.connection = None

    def connect(self):
        """Connect to the device based on protocol (SSH/Telnet)."""
        raise NotImplementedError("This method should be implemented by subclasses")

    def get_configured_SSID(self): # configured ssid getSSID method from code for this confgigreud
        [{
            "ap_mac" : "",
            "ssid": "",
            "channel_number" : "",
            "security_type" : "",
            "band" : ""
        }]
        # ssids = ["ssid1", "ssid2", "ssid3"]
        """Fetch all SSIDs from the AP."""
        raise NotImplementedError("This method should be implemented by subclasses")

    def gethosts(self):
        [{
            "ap_mac" : "",
            "host_mac" : "",
            "ssid" : ""
        }]        
        """Fetch all hosts for a specific SSID."""
        raise NotImplementedError("This method should be implemented by subclasses")

    def get_discovered_ssid(self):
        [{
            "ap_mac" : "",
            "ssid" : "",
            "strength" : "",
            "security_type" : ""
        }]
        raise NotImplementedError("This method should be implemented by subclasses")

    def getAps(self ):
        [{
            "ap_mac" : [ap_mac] | ap_mac,
            "model" : self.model,
            "ip" : self.ip
        }]
        raise NotImplementedError("This method should be implemented by subclasses")


