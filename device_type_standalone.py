import nmap
import re
import copy
from collections import defaultdict
from connection import connect, disconnect
from snmp_walker import SNMPWalker
from sqlalchemy import text
import subprocess
 # Assuming OS_TYPE_CATEGORY is in the mapping file

SNMP_DEVICE_CATEGORY = [
  {
  "SWITCH": {
    "os_keys": [
      "switch",
      "layer 2",
      "layer 3",
      "huawei",
      "cisco",
      "juniper",
      "dell",
      "netgear",
      "tp-link",
      "huawei vrp",
      "Edgecore",
      "Edgecore Networks",
      "linux"
    ],
    "nic_vendor": [
      "huawei",
      "cisco",
      "juniper",
      "dell",
      "netgear",
      "tp-link",
      "arista",
      "brocade"
    ],
    "snmp_keywords": [
      "switch",
      "sw",
      "layer 3",
      "layer 2",
      "cisco",
      "vlan",
      "trunk",
      "stp",
      "lldp",
      "spanning tree"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23
      ],
      "udp": [
        161
      ]
    },
    "lower_ports": {
      "tcp": [
        21,
        8080
      ],
      "udp": [
        1000,
        69
      ]
    },
    "keywords": [
      "switch", "layer 2", "layer 3", "cisco", "aruba", "dlink", "tplink",
            "huawei", "fiber", "netgear", "juniper", "extreme networks", "hpe",
            "brocade", "dell networking", "mikrotik", "stackable", "managed switch",
            "unmanaged switch", "poe switch", "gigabit switch", "ethernet switch", "sw"
    ]
  }
  },
  {
"NETWORKAPPLIANCE": {
    "os_keys": [
      "routeros",
      "fortios",
      "pfsense",
      "vyos",
      "openwrt",
      "pan-os",
      "juniper junos",
      "cisco ios",
      "asa",
      "sonicwall",
      "synology",
      "qnap",
      "freebsd",
      "linux",
      "NAS",
      "Thecus N8800PRO NAS device"
    ],
    "nic_vendor": [
      "cisco",
      "juniper",
      "fortinet",
      "palo alto",
      "mikrotik",
      "netgear",
      "ubiquiti",
      "synology",
      "qnap",
      "buffalo",
      "sonicwall",
      "zyxel",
      "Sony",
      "Xiaomi",
      "LG",
      "TCL",
      "Samsung",
      "Uniview",
      "QSC"
    ],
    "snmp_keywords": [
      "firewall",
      "router",
      "nas",
      "vpn",
      "wan",
      "lan",
      "gateway",
      "routing table",
      "interface",
      "bandwidth",
      "throughput",
      "traffic",
      "load balancing",
      "content filtering",
      "raid",
      "disk usage",
      "file share",
      "storage",
      "vpn connection"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23,
        500,
        4500,
        8080,
        8888,
        9000,
        1194,
        1701,
        1723,
        1700,
        554,
        6466,
        6467,
        9552,
        5353
      ],
      "udp": [
        161,
        500,
        4500,
        1194,
        1701,
        1723,
        6466,
        6467,
        9552
      ]
    },
    "lower_ports": {
      "tcp": [
        21,
        445,
        548,
        2049  
      ],
      "udp": [
        69,
        123,
        2049
      ]
    },
    "keywords": [
      "firewall",
      "router",
      "vpn",
      "gateway",
      "wan",
      "lan",
      "dmz",
      "traffic",
      "load balancing",
      "bandwidth",
      "vpn tunnel",
      "nas",
      "storage",
      "raid",
      "network drive",
      "disk usage",
      "nfs",
      "smb",
      "cifs",
      "afp",
      "backup",
      "file sharing",
      "vpn connection",
      "secure access",
      "content filtering",
      "web filtering",
      "proxy",
      "intrusion prevention",
      "intrusion detection",
      "utm",
      "HikVision",
      "BRAVIA"
    ]
  }
  },
  {
  "ACCESSPOINT": {
    "os_keys": [
      "access point",
      "wireless",
      "ap",
      "cisco",
      "ubiquiti",
      "meraki",
      "tplink",
      "dlink",
      "linksys",
      "aruba",
      "huawei",
      "wap",
      "linux",
      "openwrt"
    ],
    "nic_vendor": [
      "cisco",
      "ubiquiti",
      "aruba",
      "meraki",
      "tp-link",
      "d-link",
      "linksys",
      "netgear",
      "Cambridge",
      "Ruijie",
      "Ruijie Networks"
    ],
    "snmp_keywords": [
      "access point",
      "ap",
      "wireless",
      "ssid",
      "wlan",
      "radio",
      "signal",
      "frequency",
      "band",
      "wifi"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23,
        1812,
        1813
      ],
      "udp": [
        161,
        1812,
        1813
      ]
    },
    "lower_ports": {
      "tcp": [
        8080,
        21
      ],
      "udp": [
        69
      ]
    },
    "keywords": [
      "wap", "accesspoint", "wifi", "guangdong", "zte", "huawei", "ruckus",
            "ubiquiti", "wireless", "802.11", "hotspot", "extender", "netgear",
            "access point", "wi-fi", "wlan", "wireless lan", "wireless network",
            "wireless bridge", "wireless repeater", "mesh wifi", "enterprise wifi", "Shenzhen Bilian Electronic","FIT","AP",
            "Cambridge Industries(Group)","TACACS","zeroconf"
    ]
  }
},
{
  "ACCESSCONTROLLER": {
    "os_keys": [
      "linux",
      "embedded linux",
      "cisco ios",
      "aruba os",
      "fortios",
      "huawei vrp",
      "routeros",
      "openwrt",
      "huawei",
      "wap"
    ],
    "nic_vendor": [
      "cisco",
      "aruba",
      "ruckus",
      "fortinet",
      "meraki",
      "ubiquiti",
      "huawei",
      "tp-link",
      "d-link",
      "Cambridge"
    ],
    "snmp_keywords": [
      "access controller",
      "controller",
      "wlan",
      "wireless lan",
      "wlc",
      "ap management",
      "frequency",
      "radio",
      "vlan",
      "ssid",
      "authentication",
      "mobility",
      "roaming",
      "wifi controller"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23,
        1812,
        1813,
        5246,
        5247
      ],
      "udp": [
        161,
        1812,
        1813,
        5246,
        5247
      ]
    },
    "lower_ports": {
      "tcp": [
        8080,
        8880,
        21
      ],
      "udp": [
        69
      ]
    },
    "keywords": [
      "access controller",
      "wireless controller",
      "wlc",
      "ap management",
      "wlan",
      "ssid",
      "mobility",
      "roaming",
      "radio",
      "frequency",
      "radius",
      "tacacs",
      "vlan",
      "dhcp",
      "wifi controller",
      "wap",
      "wifi",
      "guangdong",
      "zte",
      "huawei",
      "ruckus",
      "ubiquiti",
      "wireless",
      "802.11",
      "hotspot",
      "extender",
      "netgear",
      "access point",
      "wi-fi",
      "wireless lan",
      "wireless network",
      "wireless bridge",
      "wireless repeater",
      "mesh wifi",
      "enterprise wifi",
      "Shenzhen Bilian Electronic",
      "FIT",
      "AP",
      "Cambridge Industries(Group)",
      "zeroconf"
    ]
  }
}
]

DEVICE_TYPE_CATEGORY = {
    "SWITCH": {
        "keywords": [
            "switch", "layer 2", "layer 3", "cisco", "aruba", "dlink", "tplink",
            "huawei", "fiber", "netgear", "juniper", "extreme networks", "hpe",
            "brocade", "dell networking", "mikrotik", "stackable", "managed switch",
            "unmanaged switch", "poe switch", "gigabit switch", "ethernet switch"
        ],
        "tcp_ports": [22, 23, 80, 443, 161, 830, 2000, 2001, 2002, 4786],
        "udp_ports": [161, 162, 67, 68, 123, 500]
    },
    "SERVER": {
        "keywords": [
            "server", "esxi", "proxmox", "vcenter", "virtualization", "linux", "windows",
            "apache", "nginx", "tomcat", "iis", "mysql", "mariadb", "postgresql", "database",
            "oracle", "mongodb", "ftp", "ssh", "samba", "nfs", "dns", "dhcp", "http", "https",
            "vps", "hypervisor", "docker", "kubernetes", "cloud", "active directory", "ldap",
            "rdp", "sftp", "smtp", "pop3", "imap", "webmail", "vpn", "ssh", "telnet","vmware","hyper-v"
        ],
        "tcp_ports": [22, 23, 25, 53, 80, 110, 111, 143, 443, 465, 587, 993, 995, 2049, 3306, 
                    3389, 5432, 5900, 5985, 5986, 8080, 8443, 9090, 9443, 27017, 22, 636],
        "udp_ports": [53, 67, 68, 123, 161, 162, 514, 520, 161, 500, 4500, 2049, 5353]
    },
    "ROUTER": {
        "keywords": [
            "router", "gateway", "cisco", "aruba", "dlink", "tp-link", "asus",
            "linksys", "netgear", "huawei", "routing", "wan", "modem", "adsl",
            "broadband", "juniper", "fortinet", "palo alto", "mikrotik", "edge router",
            "core router", "wireless router", "vpn router", "bgp", "ospf", "mpls"
        ],
        "tcp_ports": [22, 23, 80, 443, 161, 179, 520, 1701, 1723, 3389],
        "udp_ports": [67, 68, 123, 161, 162, 500, 1701, 4500]
    },
    "ACCESSPOINT": {
        "keywords": [
            "wap", "accesspoint", "wifi", "guangdong", "zte", "huawei", "ruckus",
            "ubiquiti", "wireless", "802.11", "hotspot", "extender", "netgear",
            "access point", "wi-fi", "wlan", "wireless lan", "wireless network",
            "wireless bridge", "wireless repeater", "mesh wifi", "enterprise wifi", "Shenzhen Bilian Electronic","FIT","AP",
            "Cambridge Industries(Group)","TACACS","zeroconf"
        ],
        "tcp_ports": [22, 23, 80, 443, 161, 2000, 8080, 8443],
        "udp_ports": [67, 68, 123, 161, 1812, 1813]
    },
    "PC": {
        "keywords": [
            "workstation", "pc", "desktop", "laptop", "personal computer",
            "windows", "linux", "mac", "intel", "amd", "dell", "hp", "lenovo",
            "asus", "acer", "microsoft surface", "thinkpad", "macbook", "netbios","msrpc"
        ],
        "tcp_ports": [135, 139, 445, 3389, 5900, 5800, 22, 80, 443,5040],
        "udp_ports": [137, 138, 1900, 5353]
    },
    "MOBILE": {
        "keywords": [
            "mobile", "smartphone", "android", "ios", "iphone", "samsung",
            "huawei", "xiaomi", "oppo", "vivo", "oneplus", "google pixel",
            "tablet", "ipad", "mobile device", "cell phone","freeciv","google"
        ],
        "tcp_ports": [80, 443, 5223, 5228],
        "udp_ports": [123, 500, 4500]
    },
    "SIPPHONE": {
        "keywords": [
            "sip phone", "ip phone", "voip phone", "sipphone", "cisco", "grandstream",
            "polycom", "astra", "avaya", "mitel", "yealink", "snom", "fanvil",
            "voip", "sip client", "softphone", "ip telephony", "unified communications","sip","sip-methods","MESSAGE","SUBSCRIBE","INVITE","sip-tls"
        ],
        "tcp_ports": [5060, 5061, 80, 443, 22],
        "udp_ports": [5060, 5061, 10000, 5004,5005]
    },
    "PRINTER": {
        "keywords": [
            "printer", "network printer", "laser printer", "inkjet printer",
            "jetdirect", "hp", "canon", "epson", "brother", "xerox", "lexmark",
            "kyocera", "ricoh", "konica minolta", "multifunction printer", "mfp",
            "print server", "airprint", "ipp"
        ],
        "tcp_ports": [80, 443, 9100, 515, 631, 21, 22, 23],
        "udp_ports": [161, 162, 631, 5353]
    },
    "FIREWALL": {
        "keywords": [
            "firewall", "security appliance", "security", "palo alto", "fortinet",
            "checkpoint", "sophos", "watchguard", "sonicwall", "juniper srx",
            "cisco asa", "barracuda", "utm", "ngfw", "next-gen firewall"
        ],
        "tcp_ports": [22, 443, 80, 8443, 4433, 10443, 3389],
        "udp_ports": [161, 162, 500, 4500]
    },
    "PBX": {
        "keywords": [
            "pbx", "ip pbx", "voip pbx", "phone system", "freepbx", "fusionpbx",
            "elastix", "trixbox", "exchange", "asterisk", "3cx", "avaya", "mitel",
            "cisco callmanager", "unified communications", "sip server", "voip server"
        ],
        "tcp_ports": [80, 443, 5038, 5060, 5061, 2000, 10000],
        "udp_ports": [5060, 5061, 10000, 5004,5005]
    },
    "IPCAM": {
        "keywords": [
            "ipcamera", "ipcam", "cctv", "camera", "cam", "webcam", "nvr", "hd ip",
            "infrared", "ptz", "h.264", "hikvision", "dahua", "axis", "bosch",
            "panasonic", "samsung techwin", "pelco", "onvif", "rtsp", "network camera", "webs"
        ],
        "tcp_ports": [80, 443, 554, 3702, 8000, 8080, 37777],
        "udp_ports": [554, 1935, 3702]
    },
    "NAS": {
        "keywords": [
            "nas", "network attached storage", "synology", "qnap", "western digital",
            "seagate", "netgear readynas", "buffalo", "asustor", "thecus",
            "file server", "storage server", "raid", "iscsi"
        ],
        "tcp_ports": [80, 443, 22, 139, 445, 111, 2049, 3260],
        "udp_ports": [137, 138, 111, 2049]
    },
    "IOTDEVICE": {
        "keywords": [
            "iot", "internet of things", "smart device", "smart home", "zigbee",
            "z-wave", "nest", "ring", "philips hue", "sonos", "amazon echo",
            "google home", "smart thermostat", "smart lock", "smart plug","webs"
        ],
        "tcp_ports": [80, 443, 8080, 1883, 8883],
        "udp_ports": [5353, 1900, 67, 68, 123]
    }
}


OS_TYPE_CATEGORY = {
    "WINDOWS": {
        "keywords": [
            "windows", 
            "windows server", 
            "win32", 
            "win64", 
            "windows xp", 
            "windows 7", 
            "windows 8", 
            "windows 10", 
            "windows 11", 
            "windows vista", 
            "windows nt", 
            "windows me", 
            "microsoft windows", 
            "win nt", 
            "windows embedded",
            "microsoft",
            "msrpc",
            "netbios"
        ],
        "tcp_ports": [135, 139, 445, 3389,5040],  # RPC, NetBIOS, SMB, RDP (TCP)
        "udp_ports": [137, 138, 445]  # NetBIOS (UDP), SMB (UDP)
    },
    "LINUX": {
        "keywords": [
            "linux", 
            "ubuntu", 
            "debian", 
            "centos", 
            "fedora", 
            "red hat", 
            "arch linux", 
            "linux mint", 
            "gentoo", 
            "kali linux", 
            "opensuse", 
            "alpine linux", 
            "rhel", 
            "linux kernel",
            "freebsd",
            "samba"
        ],
        "tcp_ports": [22, 80, 443, 3306],  # SSH, HTTP, HTTPS, MySQL (TCP)
        "udp_ports": [53, 67, 68, 123]  # DNS, DHCP, NTP (UDP)
    },
    "IPHONE": {
        "keywords": [
            "ios", 
            "iphone", 
            "ipad", 
            "ios device", 
            "apple ios", 
            "ios 14", 
            "ios 15", 
            "ios 16", 
            "iphone os", 
            "ios version", 
            "ios kernel", 
            "apple mobile"
        ],
        "tcp_ports": [5223, 443, 80],  # Apple Push Notification Service, HTTPS, HTTP (TCP)
        "udp_ports": []  # No specific known UDP ports typically used by iOS
    },
    "ANDROID": {
        "keywords": [
            "android", 
            "android os", 
            "android device", 
            "google android", 
            "android 9", 
            "android 10", 
            "android 11", 
            "android 12", 
            "android 13", 
            "android kernel", 
            "android tablet", 
            "android phone"
        ],
        "tcp_ports": [5228, 443, 80],  # Google Play Services, HTTPS, HTTP (TCP)
        "udp_ports": []  # Typically no specific UDP ports for Android
    },
    "MACOS": {
        "keywords": [
            "macos", 
            "mac os x", 
            "mac os", 
            "os x", 
            "big sur", 
            "catalina", 
            "mojave", 
            "high sierra", 
            "sierra", 
            "mavericks", 
            "el capitan", 
            "apple macos", 
            "darwin", 
            "macbook"
        ],
        "tcp_ports": [548, 88, 631, 443],  # AFP (Apple Filing Protocol), Kerberos, IPP, HTTPS (TCP)
        "udp_ports": [5353]  # mDNS (UDP)
    }
}


FINAL_MIX = [
  {
  "SWITCH": {
    "os_keys": [
      "switch",
      "layer 2",
      "layer 3",
      "huawei",
      "cisco",
      "juniper",
      "dell",
      "netgear",
      "tp-link",
      "huawei vrp",
      "Edgecore",
      "Edgecore Networks",
      "linux"
    ],
    "nic_vendor": [
      "huawei",
      "cisco",
      "juniper",
      "dell",
      "netgear",
      "tp-link",
      "arista",
      "brocade"
    ],
    "snmp_keywords": [
      "switch",
      "sw",
      "layer 3",
      "layer 2",
      "cisco",
      "vlan",
      "trunk",
      "stp",
      "lldp",
      "spanning tree"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23
      ],
      "udp": [
        161
      ]
    },
    "lower_ports": {
      "tcp": [
        21,
        8080
      ],
      "udp": [
        1000,
        69
      ]
    },
    "keywords": [
      "switch", "layer 2", "layer 3", "cisco", "aruba", "dlink", "tplink",
            "huawei", "fiber", "netgear", "juniper", "extreme networks", "hpe",
            "brocade", "dell networking", "mikrotik", "stackable", "managed switch",
            "unmanaged switch", "poe switch", "gigabit switch", "ethernet switch", "sw"
    ]
  }
},
  {
  "ACCESS_POINT": {
    "os_keys": [
      "access point",
      "wireless",
      "ap",
      "cisco",
      "ubiquiti",
      "meraki",
      "tplink",
      "dlink",
      "linksys",
      "aruba",
      "huawei",
      "wap",
      "linux",
      "openwrt"
    ],
    "nic_vendor": [
      "cisco",
      "ubiquiti",
      "aruba",
      "meraki",
      "tp-link",
      "d-link",
      "linksys",
      "netgear",
      "Cambridge",
      "Ruijie",
      "Ruijie Networks"
    ],
    "snmp_keywords": [
      "access point",
      "ap",
      "wireless",
      "ssid",
      "wlan",
      "radio",
      "signal",
      "frequency",
      "band",
      "wifi"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23,
        1812,
        1813
      ],
      "udp": [
        161,
        1812,
        1813
      ]
    },
    "lower_ports": {
      "tcp": [
        8080,
        21
      ],
      "udp": [
        69
      ]
    },
    "keywords": [
      "wap", "accesspoint", "wifi", "guangdong", "zte", "huawei", "ruckus",
            "ubiquiti", "wireless", "802.11", "hotspot", "extender", "netgear",
            "access point", "wi-fi", "wlan", "wireless lan", "wireless network",
            "wireless bridge", "wireless repeater", "mesh wifi", "enterprise wifi", "Shenzhen Bilian Electronic","FIT","AP",
            "Cambridge Industries(Group)","TACACS","zeroconf"
    ]
  }
},
{
  "ACCESS_CONTROLLER": {
    "os_keys": [
      "linux",
      "embedded linux",
      "cisco ios",
      "aruba os",
      "fortios",
      "huawei vrp",
      "routeros",
      "openwrt",
      "huawei",
      "wap"
    ],
    "nic_vendor": [
      "cisco",
      "aruba",
      "ruckus",
      "fortinet",
      "meraki",
      "ubiquiti",
      "huawei",
      "tp-link",
      "d-link",
      "Cambridge"
    ],
    "snmp_keywords": [
      "access controller",
      "controller",
      "wlan",
      "wireless lan",
      "wlc",
      "ap management",
      "frequency",
      "radio",
      "vlan",
      "ssid",
      "authentication",
      "mobility",
      "roaming",
      "wifi controller"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23,
        1812,
        1813,
        5246,
        5247
      ],
      "udp": [
        161,
        1812,
        1813,
        5246,
        5247
      ]
    },
    "lower_ports": {
      "tcp": [
        8080,
        8880,
        21
      ],
      "udp": [
        69
      ]
    },
    "keywords": [
      "access controller",
      "wireless controller",
      "wlc",
      "ap management",
      "wlan",
      "ssid",
      "mobility",
      "roaming",
      "radio",
      "frequency",
      "radius",
      "tacacs",
      "vlan",
      "dhcp",
      "wifi controller",
      "wap",
      "wifi",
      "guangdong",
      "zte",
      "huawei",
      "ruckus",
      "ubiquiti",
      "wireless",
      "802.11",
      "hotspot",
      "extender",
      "netgear",
      "access point",
      "wi-fi",
      "wireless lan",
      "wireless network",
      "wireless bridge",
      "wireless repeater",
      "mesh wifi",
      "enterprise wifi",
      "Shenzhen Bilian Electronic",
      "FIT",
      "AP",
      "Cambridge Industries(Group)",
      "zeroconf"
    ]
  }
},
{
  "VOIP_PHONE": {
    "os_keys": [
      "sip",
      "linux",
      "embedded linux",
      "asterisk",
      "cisco ios",
      "polycom firmware",
      "yealink os",
      "grandstream",
      "mitel",
      "sip firmware"
    ],
    "nic_vendor": [
      "cisco",
      "polycom",
      "yealink",
      "grandstream",
      "mitel",
      "avaya",
      "snom",
      "alcatel",
      "nec",
      "huawei",
      "unify",
      "panasonic",
      "fanvil"
    ],
    "snmp_keywords": [
      "voip phone",
      "ip phone",
      "sip",
      "h323",
      "sccp",
      "rtp",
      "voice",
      "codec",
      "call control",
      "extension",
      "pbx",
      "voice vlan",
      "call log",
      "dial plan"
    ],
    "higher_ports": {
      "tcp": [
        5060,
        5061,
        2000,
        2427,
        2727,
        3478,
        3479,
        8080
      ],
      "udp": [
        5060,
        5061,
        161,
        1719,
        1720,
        10000,
        20000,
        3478,
        3479
      ]
    },
    "lower_ports": {
      "tcp": [
        22,
        23
      ],
      "udp": [
        69,
        123,
        5004,
        5062
      ]
    },
    "keywords": [
     "sip phone", "ip phone", "voip phone", "sipphone", "cisco", "grandstream",
            "polycom", "astra", "avaya", "mitel", "yealink", "snom", "fanvil",
            "voip", "sip client", "softphone", "ip telephony", "unified communications",
            "sip","sip-methods","MESSAGE","SUBSCRIBE","INVITE","sip-tls"
    ]
  }
},
{
  "PRINTER": {
    "os_keys": [
      "printer",
      "linux",
      "embedded linux",
      "hp",
      "jetdirect",
      "epson firmware",
      "canon firmware",
      "brother firmware",
      "xerox firmware",
      "ricoh",
      "konica minolta",
      "kyocera"
    ],
    "nic_vendor": [
      "hp",
      "canon",
      "xerox",
      "brother",
      "epson",
      "ricoh",
      "konica",
      "kyocera",
      "oki",
      "lexmark",
      "sharp",
      "samsung"
    ],
    "snmp_keywords": [
      "printer",
      "print server",
      "paper",
      "toner",
      "ink",
      "print queue",
      "page count",
      "error code",
      "low toner",
      "maintenance kit",
      "drum",
      "fuser",
      "print job"
    ],
    "higher_ports": {
      "tcp": [
        9100,
        515,
        631,
        8443,
        9101,
        9102
      ],
      "udp": [
        161,
        631
      ]
    },
    "lower_ports": {
      "tcp": [
        21,
        631,
        8080
      ],
      "udp": [
        69
      ]
    },
    "keywords": [
     "printer", "network printer", "laser printer", "inkjet printer",
            "jetdirect", "hp", "canon", "epson", "brother", "xerox", "lexmark",
            "kyocera", "ricoh", "konica minolta", "multifunction printer", "mfp",
            "print server", "airprint", "ipp"
    ]
  }
},
{
  "IPCAM": {
    "os_keys": [
      "embedded linux",
      "linux",
      "openwrt",
      "hikvision",
      "dahua",
      "axis os",
      "sony firmware",
      "firmware"
    ],
    "nic_vendor": [
      "hikvision",
      "dahua",
      "axis",
      "sony",
      "panasonic",
      "bosch",
      "foscam",
      "amcrest",
      "tp-link",
      "vivotek",
      "uniview",
      "ezviz"
    ],
    "snmp_keywords": [
      "ip camera",
      "security camera",
      "network camera",
      "video stream",
      "motion detection",
      "resolution",
      "frame rate",
      "video encoding",
      "h.264",
      "h.265",
      "mpeg",
      "rtsp",
      "onvif",
      "snapshot",
      "surveillance"
    ],
    "higher_ports": {
      "tcp": [
        554,
        8000,
        8080,
        5000,
        37777
      ],
      "udp": [
        161,
        3702,
        8000,
        8080
      ]
    },
    "lower_ports": {
      "tcp": [
        23,
        21
      ],
      "udp": [
        69
      ]
    },
    "keywords": [
      "ip camera",
      "network camera",
      "onvif",
      "rtsp",
      "stream",
      "video",
      "h.264",
      "h.265",
      "mpeg",
      "motion detection",
      "resolution",
      "fps",
      "snapshot",
      "ptz",
      "infrared",
      "ir-cut",
      "firmware",
      "surveillance",
      "admin",
      "camera configuration",
      "recording",
      "live view",
      "security",
      "HikVision",
      "camera"
    ]
  }
},
{
  "SERVER": {
    "os_keys": [
      "linux",
      "windows server",
      "ubuntu",
      "centos",
      "debian",
      "red hat enterprise",
      "suse",
      "microsoft",
      "vmware",
      "freebsd",
      "solaris",
      "openbsd"
    ],
    "nic_vendor": [
      "intel",
      "broadcom",
      "hp",
      "dell",
      "supermicro",
      "ibm",
      "oracle",
      "lenovo",
      "cisco",
      "huawei"
    ],
    "snmp_keywords": [
      "server",
      "uptime",
      "cpu utilization",
      "memory usage",
      "disk space",
      "process",
      "system",
      "load average",
      "network interface",
      "services",
      "virtualization",
      "vmware",
      "hypervisor",
      "power state",
      "raid",
      "cluster"
    ],
    "higher_ports": {
      "tcp": [
        8080,
        8443,
        3306,
        1433,
        1521,
        5432,
        27017,
        6379,
        3389,
        139,
        53,
        135,
        445,
        22
      ],
      "udp": [
        162
      ]
    },
    "lower_ports": {
      "tcp": [
        21,
        25,
        110,
        143,
        389,
        636,
        993,
        995
      ],
      "udp": [
        69,
        123,
        161,
        514
      ]
    },
    "keywords": [
      "server",
      "web server",
      "database",
      "mysql",
      "postgresql",
      "sql",
      "mssql",
      "oracle",
      "mongo",
      "redis",
      "ftp",
      "ssh",
      "smtp",
      "apache",
      "lighttpd"
      "pop3",
      "imap",
      "dns",
      "dhcp",
      "virtualization",
      "vm",
      "hypervisor",
      "active directory",
      "directory service",
      "container",
      "kubernetes",
      "cloud",
      "api",
      "services",
      "storage",
      "fileserver",
      "file transfer",
      "load balancer",
      "proxy",
      "httpd",
      "nginx"
    ]
  }
},
{
  "NETWORK_APPLIANCE": {
    "os_keys": [
      "routeros",
      "fortios",
      "pfsense",
      "vyos",
      "openwrt",
      "pan-os",
      "juniper junos",
      "cisco ios",
      "asa",
      "sonicwall",
      "synology",
      "qnap",
      "freebsd",
      "linux",
      "NAS",
      "Thecus N8800PRO NAS device"
    ],
    "nic_vendor": [
      "cisco",
      "juniper",
      "fortinet",
      "palo alto",
      "mikrotik",
      "netgear",
      "ubiquiti",
      "synology",
      "qnap",
      "buffalo",
      "sonicwall",
      "zyxel",
      "Sony",
      "Xiaomi",
      "LG",
      "TCL",
      "Samsung",
      "Uniview",
      "QSC"
    ],
    "snmp_keywords": [
      "firewall",
      "router",
      "nas",
      "vpn",
      "wan",
      "lan",
      "gateway",
      "routing table",
      "interface",
      "bandwidth",
      "throughput",
      "traffic",
      "load balancing",
      "content filtering",
      "raid",
      "disk usage",
      "file share",
      "storage",
      "vpn connection"
    ],
    "higher_ports": {
      "tcp": [
        22,
        23,
        500,
        4500,
        8080,
        8888,
        9000,
        1194,
        1701,
        1723,
        1700,
        554,
        6466,
        6467,
        9552,
        5353
      ],
      "udp": [
        161,
        500,
        4500,
        1194,
        1701,
        1723,
        6466,
        6467,
        9552
      ]
    },
    "lower_ports": {
      "tcp": [
        21,
        445,
        548,
        2049  
      ],
      "udp": [
        69,
        123,
        2049
      ]
    },
    "keywords": [
      "firewall",
      "router",
      "vpn",
      "gateway",
      "wan",
      "lan",
      "dmz",
      "traffic",
      "load balancing",
      "bandwidth",
      "vpn tunnel",
      "nas",
      "storage",
      "raid",
      "network drive",
      "disk usage",
      "nfs",
      "smb",
      "cifs",
      "afp",
      "backup",
      "file sharing",
      "vpn connection",
      "secure access",
      "content filtering",
      "web filtering",
      "proxy",
      "intrusion prevention",
      "intrusion detection",
      "utm",
      "HikVision",
      "BRAVIA"
    ]
  }
},
{
  "IOT_DEVICE": {
    "os_keys": [
      "embedded linux",
      "linux",
      "rtos",
      "freebsd",
      "contiki",
      "arduino",
      "zephyr",
      "micropython",
      "tinyos",
      "mbed",
      "freertos",
      "radio",
      "RF-Space"
    ],
    "nic_vendor": [
      "broadcom",
      "qualcomm",
      "realtek",
      "mediatek",
      "nordic semiconductor",
      "esp",
      "texas instruments",
      "huawei",
      "arm",
      "intel",
      "nvidia",
      "raspberry pi foundation",
      "bosch",
      "siemens",
      "Caradon"
    ],
    "snmp_keywords": [
      "sensor",
      "actuator",
      "temperature",
      "humidity",
      "motion detection",
      "smart",
      "iot device",
      "device status",
      "battery level",
      "signal strength",
      "sensor data",
      "power consumption",
      "environment monitoring"
    ],
    "higher_ports": {
      "tcp": [
        8080,
        8443,
        5683,
        1883,
        8883,
        8888,
        10103,
        5353
      ],
      "udp": [
        5683,
        5684,
        161,
        1883
      ]
    },
    "lower_ports": {
      "tcp": [
        21,
        22,
        23
      ],
      "udp": [
        69,
        123,
        5353
      ]
    },
    "keywords": [
      "iot",
      "sensor",
      "smart home",
      "mqtt",
      "coap",
      "bluetooth",
      "zigbee",
      "z-wave",
      "environment monitoring",
      "temperature",
      "humidity",
      "battery level",
      "signal strength",
      "rfid",
      "automation",
      "controller",
      "motion sensor",
      "energy usage",
      "actuator",
      "ezrelay",
      "PocketPC/CE"
    ]
  },
  "PC": {
    "os_keys": [
      "windows",
      "windows 10",
      "windows 11",
      "windows 7",
      "mac os",
      "linux",
      "ubuntu",
      "debian",
      "red hat",
      "centos",
      "fedora",
      "freebsd",
      "Longhorn"
    ],
    "nic_vendor": [
      "intel",
      "realtek",
      "broadcom",
      "qualcomm",
      "atheros",
      "dell",
      "hp",
      "lenovo",
      "asus",
      "apple",
      "microsoft",
      "nvidia"
    ],
    "snmp_keywords": [
      "workstation",
      "computer",
      "pc",
      "desktop",
      "laptop",
      "memory usage",
      "cpu utilization",
      "disk usage",
      "operating system",
      "hostname",
      "uptime"
    ],
    "higher_ports": {
      "tcp": [
        3389,
        5900,
        5938,
        5985,
        5986,
        445,
        139
      ],
      "udp": [
        137,
        138,
        5353
      ]
    },
    "lower_ports": {
      "tcp": [
        22,
        23,
        21
      ],
      "udp": [
        123,
        161,
        162
      ]
    },
    "keywords": [
      "workstation",
      "computer",
      "desktop",
      "laptop",
      "windows",
      "macos",
      "linux",
      "ssh",
      "vnc",
      "rdp",
      "remote desktop",
      "smb",
      "cifs",
      "file sharing",
      "management",
      "cpu",
      "memory",
      "pc",
      "msrpc",
      "pando-pub"
    ]
  },
  "MOBILE_DEVICE": {
    "os_keys": [
      "android",
      "ios",
      "iphone",
      "ipad",
      "mac os",
      "apple",
      "samsung",
      "huawei",
      "oneplus",
      "xiaomi",
      "google"
    ],
    "nic_vendor": [
      "apple",
      "samsung",
      "huawei",
      "oneplus",
      "xiaomi",
      "google",
      "lg",
      "sony",
      "motorola",
      "nokia",
      "realtek",
      "mediatek",
      "qualcomm",
      "broadcom"
    ],
    "snmp_keywords": [
      "mobile",
      "smartphone",
      "tablet",
      "battery level",
      "signal strength",
      "device model",
      "serial number",
      "os version",
      "location",
      "imei",
      "wifi",
      "bluetooth"
    ],
    "higher_ports": {
      "tcp": [
        5228,
        5229,
        5230,
        5555
      ],
      "udp": [
        123,
        137
      ]
    },
    "lower_ports": {
      "tcp": [
        5228
      ],
      "udp": [
        67,
        68,
        123,
        161,
        5353
      ]
    },
    "keywords": [
      "mobile",
      "smartphone",
      "tablet",
      "android",
      "ios",
      "bluetooth",
      "wifi",
      "airdrop",
      "cloud",
      "device",
      "battery",
      "imei",
      "android debug bridge",
      "adb",
      "location services",
      "app",
      "sync",
      "push notification",
      "signal strength",
      "lte",
      "5g",
      "cellular",
      "usb"
    ]
  }
}
]

# Function to perform intense scan using nmap
def perform_nmap_scan(ip, iface):
    scanner = nmap.PortScanner()
    print(f"Running intense scan on {ip}...")
    # nmap_arg = f"-sV -O -sU -sS -p T:1-65535,U:67,68,111,123,137,138,161,162,500,554,631,1701,1812,1813,1900,1935,2049,3702,4500,5004,5005,5060,5061,5353,10000,5246,5247 -T4 -open --min-rate 300 --min-parallelism 50 --max-retries 5 --host-timeout 10m --script=rdp-ntlm-info,cups-info,snmp-info,http-title,snmp-sysdescr,sip-methods,nbstat,smb-os-discovery,upnp-info,nbstat,http-server-header,rdp-vuln-ms12-020"
    # nmap_arg = f"-e {iface} -F"
    nmap_arg = f"-e {iface} -sV -O -sU -sS -p T:1-65535,U:67,68,111,123,137,138,161,162,500,554,631,1701,1812,1813,1900,1935,2049,3702,4500,5004,5005,5060,5061,5353,10000,5246,5247 -T4 -open --min-rate 300 --min-parallelism 50 --max-retries 5 --host-timeout 10m --script=rdp-ntlm-info,cups-info,snmp-info,http-title,snmp-sysdescr,sip-methods,nbstat,smb-os-discovery,upnp-info,nbstat,http-server-header,rdp-vuln-ms12-020"
    scanner.scan(ip, arguments=nmap_arg)
    return scanner[ip]

# Function to detect OS family based on matching open ports and keywords
def detect_os_family(scan_result):
    os_family_score = defaultdict(int)
    matched_ports = defaultdict(list)
    matched_keywords = defaultdict(list)

    tcp_ports = scan_result.get('tcp', {})
    udp_ports = scan_result.get('udp', {})

    # Step 1: Match open ports with potential OS families
    possible_os_families = set()

    for os_family, details in OS_TYPE_CATEGORY.items():
        for port in tcp_ports:
            if port in details["tcp_ports"]:
                possible_os_families.add(os_family)
                os_family_score[os_family] += 1
                matched_ports[os_family].append(port)
        for port in udp_ports:
            if port in details["udp_ports"]:
                possible_os_families.add(os_family)
                os_family_score[os_family] += 1
                matched_ports[os_family].append(port)

    # Step 2: Search for keywords in Nmap output, but only for OS families matched by ports
    output = str(scan_result)

    for os_family in possible_os_families:
        for keyword in OS_TYPE_CATEGORY[os_family]["keywords"]:
            # Ensure that only full-word matches are counted
            if re.search(rf'\b{re.escape(keyword)}\b', output, re.IGNORECASE):
                os_family_score[os_family] += 1
                matched_keywords[os_family].append(keyword)

    # Step 3: Print matched keywords and ports
    print("\nOS Family Detection Details:")
    for os_family in os_family_score:
        print(f"\nOS Family: {os_family}")
        print(f"Score: {os_family_score[os_family]}")
        print(f"Matched Ports: {matched_ports[os_family]}")
        print(f"Matched Keywords: {matched_keywords[os_family]}")

    # Step 4: Return the OS family with the highest score
    if os_family_score:
        return max(os_family_score, key=os_family_score.get)
    else:
        return "Unknown OS Family"

# Function to detect device type based on matching open ports and keywords
def detect_device_type(scan_result):
    # Create a deep copy of the scan result
    modified_scan_result = copy.deepcopy(scan_result)

    # Step 1: Remove osmatch where the first osclass has accuracy < 91% from the copied scan result
    if 'osmatch' in modified_scan_result:
        filtered_osmatch = []
        for os_match in modified_scan_result['osmatch']:
            os_classes = os_match.get('osclass', [])
            # Check only the first osclass for accuracy >= 91
            if os_classes and int(os_classes[0].get('accuracy', 0)) >= 91:
                filtered_osmatch.append(os_match)

        modified_scan_result['osmatch'] = filtered_osmatch

        # Debugging output to verify filtering
        print("\nFiltered osmatch (where the first osclass has accuracy >= 91%):")
        for os_match in modified_scan_result['osmatch']:
            first_osclass = os_match['osclass'][0]
            print(f"OS: {os_match['name']}, First OS Class Accuracy: {first_osclass['accuracy']}")
    else:
        print("No osmatch found in the scan result.")

    # Step 2: Initialize device type scores, matched ports, and keywords
    device_type_score = defaultdict(int)
    matched_ports = defaultdict(list)
    matched_keywords = defaultdict(list)

    tcp_ports = scan_result.get('tcp', {})
    udp_ports = scan_result.get('udp', {})

    # Step 3: Match open ports with potential device types
    possible_device_types = set()

    for device_type, details in DEVICE_TYPE_CATEGORY.items():
        for port in tcp_ports:
            if port in details.get("tcp_ports", []):
                possible_device_types.add(device_type)
                device_type_score[device_type] += 1
                matched_ports[device_type].append(port)
        for port in udp_ports:
            if port in details.get("udp_ports", []):
                possible_device_types.add(device_type)
                device_type_score[device_type] += 1
                matched_ports[device_type].append(port)

    # Step 4: Search for keywords in the modified scan result (excluding low-accuracy osmatch)
    print(modified_scan_result)
    output = str(modified_scan_result)

    # Search for keywords in the entire modified scan result for possible device types
    for device_type in possible_device_types:
        for keyword in DEVICE_TYPE_CATEGORY[device_type].get("keywords", []):
            # Ensure that only full-word matches are counted
            if re.search(rf'\b{re.escape(keyword)}\b', output, re.IGNORECASE):
                device_type_score[device_type] += 1
                matched_keywords[device_type].append(keyword)

    # Step 5: Print matched keywords and ports
    print("\nDevice Type Detection Details:")
    for device_type in device_type_score:
        print(f"\nDevice Type: {device_type}")
        print(f"Score: {device_type_score[device_type]}")
        print(f"Matched Ports: {matched_ports[device_type]}")
        if matched_keywords[device_type]:
            print(f"Matched Keywords: {matched_keywords[device_type]}")
        else:
            print("Matched Keywords: None")

    # Step 6: Return the device type with the highest score
    if device_type_score:
        # In case of a tie, this will return one of the highest scoring device types
        return max(device_type_score, key=device_type_score.get)
    else:
        return "Unknown Device Type"

# Function to decide whether to detect OS family based on osmatch accuracy
def should_detect_os_family(scan_result):
    # Check the osmatch section for the highest accuracy
    if 'osmatch' in scan_result:
        highest_accuracy = max([int(os['accuracy']) for os in scan_result['osmatch']])
        print(f"Highest OS Match Accuracy: {highest_accuracy}%")
        # If highest accuracy is 90% or above, trust Nmap's result
        if highest_accuracy >= 90:
            print("OS Match accuracy is 90% or above. Using Nmap's OS match.")
            return False
    return True

def check_agent_or_snmp(mac):
    connection = connect()
    if mac:
        try:
            # Use parameterized query to prevent SQL injection
            query = text("""
                SELECT agent_status, is_snmp FROM hosts WHERE mac = :mac
            """)
            result = connection.execute(query, {"mac": mac})
            rows = result.fetchall()
            if rows:
                agent_status, is_snmp = rows[0]
                return agent_status, is_snmp
            else:
                return None, None
        except Exception as e:
            print("Error :-> ", f"There was an error fetching agent or snmp status: {e}")
            return None, None
        finally:
            disconnect(connection) 

# def get_agent_os_version(mac):
#     connection = connect()
#     if mac:
#         try:
#             query = f"""
#                 SELECT name, platform FROM os_version WHERE mac = '{mac}'
#             """
#             result = connection.execute(query)
#             rows = result.fetchall()
#             if rows:
#                 name, platform = rows[0]
#                 return name, platform
#             else:
#                 return None
#         except Exception as e:
#             print("Error :-> ", f"There was an error fetching agent os prop: {e}")
#             return []
#         finally:
#             disconnect(connection)

def get_agent_os_version(mac):
    connection = connect()
    if mac:
        try:
            # Use parameterized query to safely fetch data
            query = text("""
                SELECT os.name, os.platform
                FROM os_version os
                INNER JOIN hosts h ON os.device_id = h.machine_id
                WHERE h.mac = :mac
            """)
            result = connection.execute(query, {"mac": mac})
            rows = result.fetchall()
            if rows:
                name, platform = rows[0]
                return name, platform
            else:
                return None
        except Exception as e:
            print("Error :-> ", f"There was an error fetching agent OS properties: {e}")
            return []
        finally:
            disconnect(connection)

def get_snmp_conf(mac):
    connection = connect()
    devices = {}
    if mac:
        try:
            query = f"""
                SELECT DISTINCT h.mac, hi.ip, 'SNMP_DEV', sc.version, sc.community, sc.port_no, 
                                sc.authentication_protocol, sc.privacy_protocol, sc.security_user_name, 
                                sc.authentication_password, sc.private_password
                FROM hosts h 
                JOIN host_ip hi ON h.mac = hi.mac 
                JOIN snmp_configuration sc ON sc.id = h.snmp_conf
                WHERE hi.status = 1 
                AND h.is_snmp = true 
                AND h.mac = '{mac}';
            """
            query_data = connection.execute(text(query)).fetchall()
            print("SNMP QUEYR DATA", query_data)
            for device in query_data:
                mac = device[0]
                ip = device[1]
                if mac not in devices:
                    devices[mac] = {
                        'mac': mac,
                        'ips': [],
                        'category': device[2],
                        'configuration': {
                            'version': device[3],
                            'community': device[4],
                            'port_no': device[5] if device[5] is not None else 161,
                            'config': {
                                'auth_protocol': device[6] if device[6] is not None else '',
                                'priv_protocol': device[7] if device[7] is not None else '',
                                'username': device[8] if device[8] is not None else '',
                                'auth_password': device[9] if device[9] is not None else '',
                                'priv_password': device[10] if device[10] is not None else ''
                            }
                        }
                    }
                devices[mac]['ips'].append(ip)
            devices = list(devices.values())
            print(devices)
            print("Success: All SNMP devices fetched.")
            for device in devices:
                print(f"Fetched Details: {device}")
        except Exception as e:
            print("Error :-> ", f"There was an error fetching snmp conf: {e}")
            print("Error :-> ", f"There was an error fetching snmp conf: {e}")
            return []
        finally:
            print("line 53")
            disconnect(connection)
            return devices

def fetch_snmp_data(mac, ip, version, conf):
    version_map = {
        '1': 'v1',
        '2c': 'v2c',
        '3': 'v3'
    }
    snmp_version = version_map.get(version)
    user = conf['config']['username'].strip()
    auth_key = conf['config']['auth_password'].strip()
    priv_key = conf['config']['priv_password'].strip()
    auth_protocol = conf['config']['auth_protocol'].strip()
    priv_protocol = conf['config']['priv_protocol'].strip()
    community = conf['community'].strip()
    port_no = conf['port_no']

    if snmp_version is None:
        print(f"Invalid SNMP version: {version}")
        return None
    walker = SNMPWalker(ip=ip, port=port_no,community=community, version=snmp_version, user=user, auth_key=auth_key, priv_key=priv_key,
        auth_protocol=auth_protocol, priv_protocol=priv_protocol)

    try:
        walker.connect()
        sys_data = walker.getdata("1.3.6.1.2.1.1.1.0")
        sys_name = walker.getdata("1.3.6.1.2.1.1.5.0")
        walker.disconnect()
        return sys_data, sys_name

        # add sys_data and sys_name to scoring logic and get device_type
    except Exception as e:
        print(f"Error :-> ", f"There was an error fetching SNMP data: {e}")
        print("Error :-> ", f"There was an error fetching SNMP data: {e}")
        return None

def add_dict_values(dict1, dict2):
    # Create a new dictionary to store the summed values
    result = {}

    # Use the set of all keys from both dictionaries
    all_keys = set(dict1.keys()).union(set(dict2.keys()))

    for key in all_keys:
        # Get the values from each dictionary, defaulting to 0 if the key is not present
        result[key] = dict1.get(key, 0) + dict2.get(key, 0)

    return result

def find_max_key(input_dict):
    if not input_dict:
        return None  # Return None if dictionary is empty

    max_value = max(input_dict.values())  # Find the maximum value
    max_items = {key: value for key, value in input_dict.items() if value == max_value}  # Get all items with max value

    if len(max_items) > 1:
        return max_items  # Return all key-value pairs if there's a tie
    else:
        # If only one key has the max value, return it as a dictionary with one item
        key = next(iter(max_items))
        return {key: max_items[key]}

def new_detect_device_type(scan_result, DEVICE_TYPE_CATEGORY, c_type, score_amount):
    # Create a deep copy of the scan result to avoid modifying the original data
    try:
        modified_scan_result = copy.deepcopy(scan_result)

        # Initialize device type scores and matched keywords
        device_type_score = defaultdict(int)
        matched_keywords = defaultdict(list)

        # Convert modified scan result to a string for easy keyword matching
        output = str(modified_scan_result)

        # Loop through each device type in DEVICE_TYPE_CATEGORY
        for device_info in DEVICE_TYPE_CATEGORY:
            for device_type, details in device_info.items():
                # Check if the specified comparison type exists in the device details
                if c_type in details:
                    # Get the list of items to match from DEVICE_TYPE_CATEGORY for the specified c_type
                    items_to_match = details[c_type]
                    
                    # Match keywords from items_to_match against the modified scan result
                    for keyword in items_to_match:
                        # Use regex to ensure full-word matches
                        if re.search(rf'\b{re.escape(keyword)}\b', output, re.IGNORECASE):
                            # Add the specified score_amount to the device type score on a match
                            device_type_score[device_type] += score_amount
                            matched_keywords[device_type].append(keyword)

        # Print matched keywords for debugging
        # print(f"Device Type Detection Details: {iface}")
        print("Device Type Score:", dict(device_type_score))

        if device_type_score:
            for device_type, score in device_type_score.items():
                print(f"\nDevice Type: {device_type}")
                print(f"Score: {score}")
                if matched_keywords[device_type]:
                    print(f"Matched Keywords: {matched_keywords[device_type]}")
                else:
                    print("Matched Keywords: None")

        # Convert device_type_score to the required dictionary format
        result = dict(device_type_score)

        # Return the dictionary with device types and their scores
        return result if result else {}
    except Exception as e:
        print(f"Error occurred while detecting device type: {e}")
        return {}

def port_service_checking(scan_result, DEVICE_TYPE_CATEGORY, score_amount, higher=False):
    device_type_score = defaultdict(int)
    matched_ports = defaultdict(list)
    
    tcp_ports = scan_result.get('tcp', {})
    udp_ports = scan_result.get('udp', {})

    # Determine the type of ports to check based on the `higher` argument
    port_type = "higher_ports" if higher else "lower_ports"

    # Iterate through each device type in DEVICE_TYPE_CATEGORY
    for device_info in DEVICE_TYPE_CATEGORY:
        for device_type, details in device_info.items():
            # Check for TCP port matches
            for port in tcp_ports:
                if port in details[port_type]["tcp"]:
                    if scan_result['tcp'][port]['state'] == 'open':
                      device_type_score[device_type] += score_amount  # Add the score amount for each matching port
                      matched_ports[device_type].append(port)
        
            # Check for UDP port matches
            for port in udp_ports:
                if port in details[port_type]["udp"]:
                    if scan_result['udp'][port]['state'] == 'open':
                      device_type_score[device_type] += score_amount  # Add the score amount for each matching port
                      matched_ports[device_type].append(port)
    
    return device_type_score, matched_ports

def clean_nmap_output(nmap_output):
    # Remove closed and "open|filtered" ports from TCP and UDP
    if 'tcp' in nmap_output:
        nmap_output['tcp'] = {
            port: details for port, details in nmap_output['tcp'].items()
            if details['state'] not in ['closed', 'open|filtered']
        }
    if 'udp' in nmap_output:
        nmap_output['udp'] = {
            port: details for port, details in nmap_output['udp'].items()
            if details['state'] not in ['closed', 'open|filtered']
        }
    
    # Remove osmatch entries with accuracy below 90%
    if 'osmatch' in nmap_output:
        nmap_output['osmatch'] = [
            os for os in nmap_output['osmatch']
            if int(os['accuracy']) >= 90
        ]
    
    return nmap_output

def test_processes(nmap_output, DEVICE_TYPE_CATEGORY):
    final_score = defaultdict(int)
    test_specific = {}
    os_match_array = []

    try:
        # First test: OS match and clean ports according to state for only 'open' not 'open/filtered'
        if 'osmatch' in nmap_output and len(nmap_output["osmatch"]) > 0:
            for obj in nmap_output["osmatch"]:
                if int(obj.get("accuracy", 0)) >= 90:
                    os_match_array.append(obj)

            first_test_score = new_detect_device_type(os_match_array, DEVICE_TYPE_CATEGORY, 'os_keys', 5)
            print("FIRST TEST SCORE: ", first_test_score)
            for device_type, score in first_test_score.items():
                final_score[device_type] += score

            if first_test_score:
                max_first_test_score = max(first_test_score.values())
                first_test_winners = [device for device, score in first_test_score.items() if score == max_first_test_score]
                for winner in first_test_winners:
                    final_score[winner] += 1
                test_specific["first"] = first_test_winners
                print("After First Test - Final Score:", final_score)
                print("After First Test - Test Specific:", test_specific)

        # Second test: NIC vendor
        if "vendor" in nmap_output and len(nmap_output["vendor"]) > 0:
            second_test_score = new_detect_device_type(nmap_output["vendor"], DEVICE_TYPE_CATEGORY, 'nic_vendor', 4)
            print("SECOND TEST SCORE: ", second_test_score)
            for device_type, score in second_test_score.items():
                final_score[device_type] += score

            if second_test_score:
                max_second_test_score = max(second_test_score.values())
                second_test_winners = [device for device, score in second_test_score.items() if score == max_second_test_score]
                for winner in second_test_winners:
                    final_score[winner] += 1
                test_specific["second"] = second_test_winners
                print("After Second Test - Final Score:", final_score)
                print("After Second Test - Test Specific:", test_specific)

        # Third test: Higher ports
        device_type_score_third_test, matched_ports_third_test = port_service_checking(nmap_output, DEVICE_TYPE_CATEGORY, score_amount=3, higher=True)
        print("THIRD TEST SCORE: ", device_type_score_third_test)
        for device_type, score in device_type_score_third_test.items():
            final_score[device_type] += score

        if device_type_score_third_test:
            max_higher_ports_score = max(device_type_score_third_test.values())
            third_test_winners = [device for device, score in device_type_score_third_test.items() if score == max_higher_ports_score]
            for winner in third_test_winners:
                final_score[winner] += 1
            test_specific["third"] = third_test_winners
            print("After Third Test - Final Score:", final_score)
            print("After Third Test - Test Specific:", test_specific)

        # Fourth test: Lower ports
        device_type_score_fourth_test, matched_ports_fourth_test = port_service_checking(nmap_output, DEVICE_TYPE_CATEGORY, score_amount=1, higher=False)
        print("FOURTH TEST SCORE: ", device_type_score_fourth_test)
        for device_type, score in device_type_score_fourth_test.items():
            final_score[device_type] += score

        if device_type_score_fourth_test:
            max_lower_ports_score = max(device_type_score_fourth_test.values())
            fourth_test_winners = [device for device, score in device_type_score_fourth_test.items() if score == max_lower_ports_score]
            for winner in fourth_test_winners:
                final_score[winner] += 1
            test_specific["fourth"] = fourth_test_winners
            print("After Fourth Test - Final Score:", final_score)
            print("After Fourth Test - Test Specific:", test_specific)

        # Fifth test: Non-OS match
        # non_os_match_array = nmap_output.pop('osmatch', None) # its taking
        non_os_match_array = nmap_output.copy()
        if "osmatch" in non_os_match_array:
          del non_os_match_array["osmatch"]
        print("NON OS MATCH ARRAY" , non_os_match_array)
        if non_os_match_array:
            non_os_match_score = new_detect_device_type(non_os_match_array, DEVICE_TYPE_CATEGORY, 'keywords', 1)
            print("FIFTH TEST SCORE: ", non_os_match_score)
            for device_type, score in non_os_match_score.items():
                final_score[device_type] += score

            if non_os_match_score:
                max_non_os_match_score = max(non_os_match_score.values())
                fifth_test_winners = [device for device, score in non_os_match_score.items() if score == max_non_os_match_score]
                for winner in fifth_test_winners:
                    final_score[winner] += 1
                test_specific["fifth"] = fifth_test_winners
                print("After Fifth Test - Final Score:", final_score)
                print("After Fifth Test - Test Specific:", test_specific)

        # Check for tie in final scores
        print("FINAL SCORE:", final_score)
        print("TEST SPECIFIC:", test_specific)
        
        if final_score:  # Ensure final_score is not empty before calling max()
            print("INFO", "hostscanner", f"FINAL SCORE : {final_score}")
            max_score = max(final_score.values())
            max_keys = [key for key, value in final_score.items() if value == max_score]

            if len(max_keys) > 1:
                for test_name in ["first", "second", "third", "fourth", "fifth"]:
                    if test_name in test_specific:
                        test_winners = test_specific[test_name]
                        eligible_winners = [winner for winner in max_keys if winner in test_winners]
                        
                        if len(eligible_winners) == 1:
                            return eligible_winners[0]
                
                # If no unique winner is determined after all tests
                return "OTHERS"
            else:
                # Only one max_key exists
                return max_keys[0]
        else:
            return "PC"

    except Exception as e:
        print("Error :-> ", f"There was an error in test_processes: {e}")
        print("Error :-> ", f"There was an error in test_processes: {e}")
        return "PC"  # Return "PC" in case of any error
    
def is_port_161_open(nmap_output):
    # Check if '161' exists in TCP ports with state 'open'
    if "tcp" in nmap_output:
        tcp_ports = nmap_output["tcp"]
        if 161 in tcp_ports and tcp_ports[161].get("state") == "open":
            return True

    # Check if '161' exists in UDP ports with state 'open'
    if "udp" in nmap_output:
        udp_ports = nmap_output["udp"]
        if 161 in udp_ports and udp_ports[161].get("state") == "open":
            return True

    return False

def get_netbios_name(ip):
    """
    Executes nbtscan for the given IP and extracts the NetBIOS Name.
    Args:
        ip (str): The IP address to scan.
    Returns:
        str: The extracted NetBIOS Name, or None if no name is found.
    """
    try:
        # Run the nbtscan command
        command = f"nbtscan {ip}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # Check if the command executed successfully
        if result.returncode != 0:
            print(f"Error: Command failed with return code {result.returncode}")
            print(f"Stderr: {result.stderr}")
            return None

        # Print the raw output for debugging
        print("Command Output:")
        print(result.stdout)

        # Split output into lines and process
        lines = result.stdout.splitlines()
        
        # Filter out informational or separator lines
        filtered_lines = [
            line for line in lines
            if not (line.startswith("Doing NBT") or line.startswith("IP address") or line.startswith("-"))
        ]

        # If there are no valid lines left, return None
        if not filtered_lines:
            return None

        # Process the last line
        last_line = filtered_lines[-1].strip()
        parts = last_line.split()

        # Ensure the line contains at least two columns (IP and NetBIOS Name)
        if len(parts) >= 2:
            return parts[1]  # NetBIOS Name is the second column

        # If the line doesn't have enough columns, return None
        return None
    except Exception as e:
        print(f"Error during execution: {e}")
        return None

# Main function to run both OS family and device type detection
def main():
    ip_address = input("Enter the IP address to scan: ")
    mac = input("Enter the mac to scan: ")
    iface = input("Enter the iface: ")
    try:
        scan_result = perform_nmap_scan(ip_address, iface)
        print("BEFORE",scan_result)
        scan_result = clean_nmap_output(scan_result)
        print("AFTER",scan_result)
        
        agent_status, snmp_status = check_agent_or_snmp(mac)
        print("AGENT AND SNMP STATUS", agent_status, snmp_status)
        device_type = ""
        os_family = ""
        os = ""
        # hd = host_details(host['ip'], iface ,host['mac'])

        snmp_according_to_port = is_port_161_open(scan_result)
        print("SNMP SCC TO PORT", snmp_according_to_port)

        if agent_status:
            device_type = "PC"
            os, os_family = get_agent_os_version(mac)


        elif snmp_status:
            snmp_devices = get_snmp_conf(mac)
            if snmp_devices:
                for device in snmp_devices:
                    snmp_conf = device.get('configuration')
                    snmp_version = snmp_conf['version'].strip()
                    sys_data, sys_name = fetch_snmp_data(mac, ip_address, snmp_version, snmp_conf)
                    concatenated_data = str(sys_data) + str(sys_name)
                    print("SNMP concatenated_data", concatenated_data)
                    snmp_test_score = new_detect_device_type(concatenated_data, SNMP_DEVICE_CATEGORY, 'snmp_keywords', 1)

                    # Get the device type with the highest score
                    if snmp_test_score:
                        max_score = max(snmp_test_score.values())  # Find the highest score
                        max_keys = [key for key, value in snmp_test_score.items() if value == max_score]  # Get keys with the max score
                        
                        # If there are multiple max score keys, return the first one
                        result = max_keys[0] if max_keys else "SWITCH"
                        device_type = result
                        
                        print(f"Highest scoring device type: {result} with score: {max_score}")
            else:
                device_type = test_processes(scan_result, FINAL_MIX)
                        
        else:
          device_type = test_processes(scan_result,FINAL_MIX)
        print("MAIN DEVICE TYPE", device_type)
        host_name_nbtscan = get_netbios_name(ip_address)
        print("HOSTNAME-unclean", host_name_nbtscan)
        if host_name_nbtscan:
            host_name_clean = host_name_nbtscan.strip("'\"")
            print("HOSTNAME",host_name_clean)
        # Check if we should detect OS family based on osmatch accuracy
        if should_detect_os_family(scan_result):
            os_family = detect_os_family(scan_result)
        else:
            os_family = scan_result['osmatch'][0]['osclass'][0]['osfamily']  # Use the highest osmatch result
        
        # device_type = detect_device_type(scan_result)
        if 'osmatch' in scan_result and len(scan_result['osmatch']) > 0:
            os_name = scan_result['osmatch'][0]['name']
            print(f"\nFinal Detected OS : {os_name}")

        print(f"\nFinal Detected OS Family: {os_family}")
        print(f"Final Detected Device Type: {device_type}")
    except Exception as e:
        print(f"An error occurred during scanning: {e}")

# Uncomment the following line to run the script
main()