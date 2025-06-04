# main file for meshcentral testing
from meshcentral_client import MeshCentralClient
from meshcentral_adaptor import MeshCentralAdaptor
import time
import json

from connection import connect, disconnect

def load_meshcentral_config(config_path="/netviss-storage/meshcentral_config.json"):
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)

        login_url = config.get("url", "")
        ws_url = config.get("ws", "")

        admin = config.get("admin", {})
        username = admin.get("username", "")
        password = admin.get("password", "")

        return {
            "login_url": login_url,
            "ws_url": ws_url,
            "username": username,
            "password": password
        }

    except FileNotFoundError:
        print(f"Config file not found at {config_path}")
    except json.JSONDecodeError:
        print("Invalid JSON format in meshcentral_config.json")
    except Exception as e:
        print(f"Error loading meshcentral config: {e}")
    
    return None

# meshcentral_properety_cache = {'xyz_110': {'process': '0, [System Process]\r\n4, System\r\n124, Registry\r\n132, SYSTEM, MoUsoCoreWorker.exe\r\n296, MsMpEng.exe\r\n384, smss.exe\r\n448, NETWORK SERVICE, svchost.exe\r\n484, csrss.exe\r\n560, wininit.exe\r\n580, csrss.exe\r\n660, SYSTEM, winlogon.exe\r\n704, services.exe\r\n712, SYSTEM, lsass.exe\r\n848, SYSTEM, svchost.exe\r\n868, LOCAL SERVICE, svchost.exe\r\n872, UMFD-0, fontdrvhost.exe\r\n880, UMFD-1, fontdrvhost.exe\r\n976, NETWORK SERVICE, svchost.exe\r\n1020, SYSTEM, svchost.exe\r\n1080, LOCAL SERVICE, svchost.exe\r\n1096, SYSTEM, svchost.exe\r\n1104, LOCAL SERVICE, svchost.exe\r\n1216, DWM-1, dwm.exe\r\n1240, LOCAL SERVICE, svchost.exe\r\n1284, LOCAL SERVICE, svchost.exe\r\n1384, LOCAL SERVICE, svchost.exe\r\n1520, SYSTEM, svchost.exe\r\n1560, SYSTEM, svchost.exe\r\n1576, NETWORK SERVICE, svchost.exe\r\n1604, zirozen, msedge.exe\r\n1672, SYSTEM, svchost.exe\r\n1680, LOCAL SERVICE, svchost.exe\r\n1688, SYSTEM, svchost.exe\r\n1696, SYSTEM, svchost.exe\r\n1784, LOCAL SERVICE, svchost.exe\r\n1812, Memory Compression\r\n1912, SYSTEM, svchost.exe\r\n1976, SYSTEM, svchost.exe\r\n1992, LOCAL SERVICE, svchost.exe\r\n2056, SYSTEM, svchost.exe\r\n2064, LOCAL SERVICE, svchost.exe\r\n2120, LOCAL SERVICE, svchost.exe\r\n2128, SYSTEM, svchost.exe\r\n2216, LOCAL SERVICE, svchost.exe\r\n2324, SYSTEM, svchost.exe\r\n2360, NETWORK SERVICE, svchost.exe\r\n2392, LOCAL SERVICE, svchost.exe\r\n2400, NETWORK SERVICE, svchost.exe\r\n2424, SYSTEM, AnyDesk.exe\r\n2448, LOCAL SERVICE, svchost.exe\r\n2460, LOCAL SERVICE, svchost.exe\r\n2520, SYSTEM, svchost.exe\r\n2536, SYSTEM, svchost.exe\r\n2576, NETWORK SERVICE, svchost.exe\r\n2676, zirozen, msedge.exe\r\n2700, LOCAL SERVICE, svchost.exe\r\n2760, SYSTEM, svchost.exe\r\n2764, SYSTEM, spoolsv.exe\r\n2816, LOCAL SERVICE, svchost.exe\r\n2892, SYSTEM, blnsvr.exe\r\n2920, SYSTEM, MeshAgent.exe\r\n3044, SYSTEM, svchost.exe\r\n3060, zirozen, UserOOBEBroker.exe\r\n3104, SYSTEM, svchost.exe\r\n3124, SYSTEM, svchost.exe\r\n3252, SYSTEM, svchost.exe\r\n3292, LOCAL SERVICE, svchost.exe\r\n3420, zirozen, svchost.exe\r\n3520, SYSTEM, svchost.exe\r\n3624, SYSTEM, svchost.exe\r\n3648, SYSTEM, WmiPrvSE.exe\r\n3836, zirozen, SystemSettings.exe\r\n3840, zirozen, AnyDesk.exe\r\n3900, LOCAL SERVICE, svchost.exe\r\n3932, SYSTEM, svchost.exe\r\n4060, zirozen, sihost.exe\r\n4084, zirozen, svchost.exe\r\n4184, zirozen, taskhostw.exe\r\n4220, svchost.exe\r\n4304, SYSTEM, svchost.exe\r\n4368, zirozen, ctfmon.exe\r\n4432, zirozen, taskhostw.exe\r\n4512, LOCAL SERVICE, svchost.exe\r\n4660, SYSTEM, SearchIndexer.exe\r\n4696, zirozen, msedge.exe\r\n4724, zirozen, svchost.exe\r\n4816, zirozen, explorer.exe\r\n4848, zirozen, RuntimeBroker.exe\r\n4948, LOCAL SERVICE, svchost.exe\r\n4960, SYSTEM, svchost.exe\r\n5124, zirozen, msedge.exe\r\n5180, MpDefenderCoreService.exe\r\n5452, zirozen, svchost.exe\r\n5532, SYSTEM, svchost.exe\r\n5768, SYSTEM, AggregatorHost.exe\r\n5908, LOCAL SERVICE, svchost.exe\r\n5992, zirozen, ShellExperienceHost.exe\r\n6056, SYSTEM, svchost.exe\r\n6180, zirozen, RuntimeBroker.exe\r\n6276, zirozen, StartMenuExperienceHost.exe\r\n6368, zirozen, OneDrive.exe\r\n6620, SYSTEM, svchost.exe\r\n6640, LOCAL SERVICE, WmiPrvSE.exe\r\n6684, SYSTEM, svchost.exe\r\n6692, zirozen, RuntimeBroker.exe\r\n6792, zirozen, msedge.exe\r\n7048, zirozen, SearchApp.exe\r\n7556, zirozen, SearchApp.exe\r\n7592, zirozen, LockApp.exe\r\n7764, zirozen, RuntimeBroker.exe\r\n7776, SYSTEM, svchost.exe\r\n7932, SYSTEM, svchost.exe\r\n8036, LOCAL SERVICE, svchost.exe\r\n8256, zirozen, msedge.exe\r\n8332, zirozen, TabTip.exe\r\n8516, zirozen, TextInputHost.exe\r\n8536, zirozen, AnyDesk.exe\r\n8608, svchost.exe\r\n8668, zirozen, ApplicationFrameHost.exe\r\n8684, zirozen, SecurityHealthSystray.exe\r\n8716, SecurityHealthService.exe\r\n9032, zirozen, RuntimeBroker.exe\r\n9076, zirozen, dllhost.exe\r\n9188, zirozen, msedge.exe\r\n9408, SYSTEM, dllhost.exe\r\n9596, zirozen, taskhostw.exe\r\n9624, NisSrv.exe\r\n9704, zirozen, msedge.exe\r\n9848, SYSTEM, svchost.exe\r\n10012, zirozen, msedge.exe\r\n', 'cpuinfo': '{\n "hardware": {\n  "windows": {\n   "memory": [\n    {\n     "Capacity": "6442450944",\n     "Caption": "Physical Memory",\n     "CreationClassName": "Win32_PhysicalMemory",\n     "Description": "Physical Memory",\n     "DeviceLocator": "DIMM 0",\n     "FormFactor": 8,\n     "Manufacturer": "QEMU",\n     "MemoryType": 9,\n     "Name": "Physical Memory",\n     "SMBIOSMemoryType": 7,\n     "Tag": "Physical Memory 0",\n     "TypeDetail": 2\n    }\n   ],\n   "osinfo": {\n    "BootDevice": "\\\\Device\\\\HarddiskVolume1",\n    "BuildNumber": "19045",\n    "BuildType": "Multiprocessor Free",\n    "Caption": "Microsoft Windows 10 Pro",\n    "CodeSet": "1252",\n    "CountryCode": "1",\n    "CreationClassName": "Win32_OperatingSystem",\n    "CSCreationClassName": "Win32_ComputerSystem",\n    "CSName": "DESKTOP-S30H78G",\n    "CurrentTimeZone": 240,\n    "DataExecutionPrevention_32BitApplications": true,\n    "DataExecutionPrevention_Available": true,\n    "DataExecutionPrevention_Drivers": true,\n    "DataExecutionPrevention_SupportPolicy": 2,\n    "EncryptionLevel": 256,\n    "ForegroundApplicationBoost": 2,\n    "InstallDate": "20250514011636.000000+240",\n    "LastBootUpTime": "20250523173702.225909+240",\n    "Locale": "0409",\n    "Manufacturer": "Microsoft Corporation",\n    "MaxNumberOfProcesses": -1,\n    "Name": "Microsoft Windows 10 Pro|C:\\\\Windows|\\\\Device\\\\Harddisk0\\\\Partition2",\n    "NumberOfProcesses": 131,\n    "NumberOfUsers": 2,\n    "OperatingSystemSKU": 48,\n    "OSArchitecture": "64-bit",\n    "OSLanguage": 1033,\n    "OSProductSuite": 256,\n    "OSType": 18,\n    "Primary": true,\n    "ProductType": 1,\n    "RegisteredUser": "netviss",\n    "SerialNumber": "00330-80000-00000-AA507",\n    "SizeStoredInPagingFiles": "1703936",\n    "Status": "OK",\n    "SuiteMask": 272,\n    "SystemDevice": "\\\\Device\\\\HarddiskVolume2",\n    "SystemDirectory": "C:\\\\Windows\\\\system32",\n    "SystemDrive": "C:",\n    "Version": "10.0.19045"\n   },\n   "partitions": [\n    {\n     "BlockSize": "512",\n     "Bootable": true,\n     "BootPartition": true,\n     "Caption": "Disk #0, Partition #0",\n     "CreationClassName": "Win32_DiskPartition",\n     "Description": "Installable File System",\n     "DeviceID": "Disk #0, Partition #0",\n     "Name": "Disk #0, Partition #0",\n     "NumberOfBlocks": "102400",\n     "PrimaryPartition": true,\n     "Size": "52428800",\n     "StartingOffset": "1048576",\n     "SystemCreationClassName": "Win32_ComputerSystem",\n     "SystemName": "DESKTOP-S30H78G"\n    },\n    {\n     "BlockSize": "512",\n     "Caption": "Disk #0, Partition #1",\n     "CreationClassName": "Win32_DiskPartition",\n     "Description": "Installable File System",\n     "DeviceID": "Disk #0, Partition #1",\n     "Index": 1,\n     "Name": "Disk #0, Partition #1",\n     "NumberOfBlocks": "124649957",\n     "PrimaryPartition": true,\n     "Size": "63820777984",\n     "StartingOffset": "53477376",\n     "SystemCreationClassName": "Win32_ComputerSystem",\n     "SystemName": "DESKTOP-S30H78G"\n    },\n    {\n     "BlockSize": "512",\n     "Caption": "Disk #0, Partition #2",\n     "CreationClassName": "Win32_DiskPartition",\n     "Description": "Unknown",\n     "DeviceID": "Disk #0, Partition #2",\n     "Index": 2,\n     "Name": "Disk #0, Partition #2",\n     "NumberOfBlocks": "1069056",\n     "PrimaryPartition": true,\n     "Size": "547356672",\n     "StartingOffset": "63875055616",\n     "SystemCreationClassName": "Win32_ComputerSystem",\n     "SystemName": "DESKTOP-S30H78G"\n    }\n   ],\n   "cpu": [\n    {\n     "Caption": "Intel64 Family 15 Model 107 Stepping 1",\n     "DeviceID": "CPU0",\n     "Manufacturer": "GenuineIntel",\n     "MaxClockSpeed": 2095,\n     "Name": "QEMU Virtual CPU version 2.5+",\n     "SocketDesignation": "CPU 0"\n    }\n   ],\n   "gpu": [\n    {\n     "Name": "Microsoft Basic Display Adapter",\n     "CurrentHorizontalResolution": 1024,\n     "CurrentVerticalResolution": 768\n    }\n   ],\n   "drives": [\n    {\n     "Caption": "QEMU QEMU HARDDISK SCSI Disk Device",\n     "DeviceID": "\\\\\\\\.\\\\PHYSICALDRIVE0",\n     "Model": "QEMU QEMU HARDDISK SCSI Disk Device",\n     "Partitions": 3,\n     "Size": "64420392960",\n     "Status": "OK"\n    }\n   ],\n   "volumes": {\n    "C": {\n     "type": "NTFS",\n     "size": 63820775424,\n     "sizeremaining": 38427140096\n    }\n   }\n  },\n  "identifiers": {\n   "bios_date": "20140401000000.000000+000",\n   "bios_vendor": "SeaBIOS",\n   "bios_version": "rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org",\n   "bios_mode": "Legacy",\n   "product_uuid": "234DAE0E-F34B-4918-A965-B8F9C889231A",\n   "product_name": "Standard PC (Q35 + ICH9, 2009)",\n   "gpu_name": [\n    "Microsoft Basic Display Adapter"\n   ],\n   "storage_devices": [\n    {\n     "Caption": "QEMU QEMU HARDDISK SCSI Disk Device",\n     "Model": "QEMU QEMU HARDDISK SCSI Disk Device",\n     "Size": "64420392960"\n    }\n   ],\n   "cpu_name": "QEMU Virtual CPU version 2.5+"\n  },\n  "agentvers": {\n   "openssl": "1.1.1s",\n   "duktape": "v2.6.0",\n   "commitDate": "2025-03-06T21:44:07.000Z",\n   "commitHash": "28d67274264e140e0c7a4254ad0e32865d5c4a13",\n   "compileTime": "18:56:58, Mar  6 2025"\n  },\n  "network": {\n   "dns": [\n    "192.168.41.1"\n   ]\n  }\n },\n "pendingReboot": "File Rename",\n "hash": "056DBDD721E0ED98306F3D8FF35844A87A5E8C7C6B163798DC510736D2FD54DFAF33AF0764979553382B4F188B5C6365"\n}'}}
meshcentral_properety_cache = {}
meshcentral_config = load_meshcentral_config()
print("PROPERTY CACHE : ", meshcentral_properety_cache)
# LOGIN_URL = "https://192.168.15.15:8086/"
# WS_URL = "wss://192.168.15.15:8086/control.ashx"
# ORIGIN = "https://192.168.30.22"
# NODE_ID = "node//eSP6Du3A87X@Rb1CR4MW9xRUU31DoP6XH2CR7BGMioC3kJzcm0t2VdJ3e6YyS3nP"
# FILE_PATH = "mesh.json"

# ws = "wss://192.168.15.15:8086/control.ashx"
# origin = "https://192.168.30.22"
LOGIN_URL = meshcentral_config["login_url"]
WS_URL = meshcentral_config["ws_url"]
USERNAME = meshcentral_config["username"]
PASSWORD = meshcentral_config["password"]
ORIGIN = "https://192.168.30.22"
NODE_ID = "node//OYQvb11AsWpc7BnYH2BaHFwvAbEUerhbAnRd@3CZrj2BvnwJb0hiJmk86kSvkJi7" 
print("LOGIN_URL" , LOGIN_URL)
print("WS_URL" , WS_URL)
# nv-win = node//1yc7jMvR5ofHMykNQCQhJ3mDHe6AQi7Z4Xp6z3UdPXozgl@G24b@mdSudH$NdlEM
# "node//OYQvb11AsWpc7BnYH2BaHFwvAbEUerhbAnRd@3CZrj2BvnwJb0hiJmk86kSvkJi7" # nv 21.10 mesh
agent_client = MeshCentralClient(LOGIN_URL, WS_URL, ORIGIN, NODE_ID,  USERNAME, PASSWORD)
agent_client.login_and_connect()
connection = connect()

# node_id = "node//OYQvb11AsWpc7BnYH2BaHFwvAbEUerhbAnRd@3CZrj2BvnwJb0hiJmk86kSvkJi7"
# node//eSP6Du3A87X@Rb1CR4MW9xRUU31DoP6XH2CR7BGMioC3kJzcm0t2VdJ3e6YyS3nP - NV-WIN
# node//VEnz2d4lFKBwGNRYZfr9DTPj45ge$NQCYWd0UP7rhXXkYURiu$A1AyzbnAOSXqs8 - DESKTOP-S30H78G
# node//eSP6Du3A87X@Rb1CR4MW9xRUU31DoP6XH2CR7BGMioC3kJzcm0t2VdJ3e6YyS3nP
device_id = "a4be7805-4d48-4096-b33c-0dde2fb7e58a"
adaptor = MeshCentralAdaptor(agent_client,connection, NODE_ID, device_id)

time.sleep(5)

# process_data = adaptor.get_process(real_time=False, cache_data=meshcentral_properety_cache)
# print("PROCESS DATA", process_data)
all_propertie_status = adaptor.get_and_set_all_data() # add all properties here

print(f"Agent properties status : {all_propertie_status}")

meshcentral_properety_cache[device_id] = all_propertie_status['data']

