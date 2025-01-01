from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData,ObjectType, ObjectIdentity, getCmd, nextCmd, UsmUserData,usmHMACMD5AuthProtocol, usmDESPrivProtocol
from typing import List, Dict
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class Interface:
    def __init__(self, ifIndex, ifDescr, ifType, ifSpeed, ifPhysicalAddress, ifAdminStatus, ifOperStatus, ifInOctets, ifOutOctets, duplex):
        self.ifIndex = ifIndex
        self.ifDescr = ifDescr
        self.ifType = ifType
        self.ifSpeed = ifSpeed
        self.ifPhysicalAddress = ifPhysicalAddress
        self.ifAdminStatus = ifAdminStatus
        self.ifOperStatus = ifOperStatus
        self.ifInOctets = ifInOctets
        self.ifOutOctets = ifOutOctets
        self.duplex = duplex

class Device:
    def __init__(self, sysDescr, sysObjectID, sysUptime, sysContact, sysName, sysLocation, fanSpeed, cpu, memory, serial_no):
        self.sysDescr = sysDescr
        self.sysObjectID = sysObjectID
        self.sysUptime = sysUptime
        self.sysContact = sysContact
        self.sysName = sysName
        self.sysLocation = sysLocation
        self.fanSpeed = fanSpeed
        self.cpu = cpu
        self.memory = memory
        self.serial_no = serial_no

class Host:
    def __init__(self, macAddress, portNumber):
        self.macAddress = macAddress
        self.portNumber = portNumber

class SNMPWalker:
    # def __init__(self, ip: str, community: str, version: int, port: int = 161):
    #     self.ip = ip
    #     self.community = community
    #     self.version = version
    #     self.port = port
    #     self.session = None

    def __init__(self, ip, port,community, version,user, auth_key, priv_key, auth_protocol, priv_protocol):
        self.version = version
        self.ip = ip
        self.port = port
        self.community = community
        self.user = user
        self.auth_key = auth_key
        self.priv_key = priv_key
        self.auth_protocol = auth_protocol or usmHMACMD5AuthProtocol
        self.priv_protocol = priv_protocol or usmDESPrivProtocol
        self.engine = None
        self.target = None
        self.context = None
        self.user_data = None
        self.community_data = None

    # def connect(self):
    #     self.session = SnmpEngine()
    #     logging.info(f"Connected to SNMP device at {self.ip}")

    def connect(self):
        """Establishes connection based on SNMP version"""
        self.engine = SnmpEngine()
        self.target = UdpTransportTarget((self.ip, self.port))
        self.context = ContextData()

        if self.version == 'v1':
            self.community_data = CommunityData(self.community, mpModel=0)
        elif self.version == 'v2c':
            self.community_data = CommunityData(self.community, mpModel=1)
        elif self.version == 'v3':
            self.user_data = UsmUserData(
                self.user, self.auth_key, self.priv_key,
                authProtocol=self.auth_protocol,
                privProtocol=self.priv_protocol
            )
        else:
            raise ValueError("Unsupported SNMP version. Supported versions are 'v1', 'v2c', 'v3'.")

    def disconnect(self):
        if self.engine:
            self.engine = None
            logging.info(f"Disconnected from SNMP device at {self.ip}")

    # def get_interface_details(self) -> List[Interface]:
    #     oids = {
    #         '1.3.6.1.2.1.2.2.1.1': 'ifIndex',
    #         '1.3.6.1.2.1.2.2.1.2': 'ifDescr',
    #         '1.3.6.1.2.1.2.2.1.3': 'ifType',
    #         '1.3.6.1.2.1.2.2.1.5': 'ifSpeed',
    #         '1.3.6.1.2.1.2.2.1.6': 'ifPhysicalAddress',
    #         '1.3.6.1.2.1.2.2.1.7': 'ifAdminStatus',
    #         '1.3.6.1.2.1.2.2.1.8': 'ifOperStatus',
    #         '1.3.6.1.2.1.2.2.1.10': 'ifInOctets',
    #         '1.3.6.1.2.1.2.2.1.16': 'ifOutOctets',
    #         '1.3.6.1.2.1.10.7.2.1.19' : 'duplex'
    #     }

    #     results = {key: {} for key in oids.values()}
    #     for oid, attr in oids.items():
    #         g = nextCmd(
    #             self.engine,
    #             self.community_data if self.version in ['v1', 'v2c'] else self.user_data,
    #             self.target,
    #             self.context,
    #             ObjectType(ObjectIdentity(oid)),
    #             lexicographicMode=False
    #         )
    #         for errorIndication, errorStatus, errorIndex, varBinds in g:
    #             if errorIndication or errorStatus:
    #                 logging.error(f"Error fetching {attr}: {errorIndication or errorStatus}")
    #                 break
    #             for varBind in varBinds:
    #                 index = varBind[0].prettyPrint().split('.')[-1]
    #                 results[attr][index] = str(varBind[1].prettyPrint())

    #     interfaces = []
    #     for ifIndex in sorted(results['ifIndex'].keys()):
    #         interfaces.append(Interface(
    #             ifIndex=results['ifIndex'].get(ifIndex, ''),
    #             ifDescr=results['ifDescr'].get(ifIndex, ''),
    #             ifType=results['ifType'].get(ifIndex, ''),
    #             ifSpeed=results['ifSpeed'].get(ifIndex, ''),
    #             ifPhysicalAddress=results['ifPhysicalAddress'].get(ifIndex, ''),
    #             ifAdminStatus=results['ifAdminStatus'].get(ifIndex, ''),
    #             ifOperStatus=results['ifOperStatus'].get(ifIndex, ''),
    #             ifInOctets=results['ifInOctets'].get(ifIndex, ''),
    #             ifOutOctets=results['ifOutOctets'].get(ifIndex, ''),
    #             duplex=results['duplex'].get(ifIndex, '')
    #         ))

    #     return interfaces

    def get_interface_details(self) -> List[Interface]:
        oids = {
            '1.3.6.1.2.1.2.2.1.1': 'ifIndex',
            '1.3.6.1.2.1.2.2.1.2': 'ifDescr',
            '1.3.6.1.2.1.2.2.1.3': 'ifType',
            '1.3.6.1.2.1.2.2.1.5': 'ifSpeed',
            '1.3.6.1.2.1.2.2.1.6': 'ifPhysicalAddress',
            '1.3.6.1.2.1.2.2.1.7': 'ifAdminStatus',
            '1.3.6.1.2.1.2.2.1.8': 'ifOperStatus',
            '1.3.6.1.2.1.2.2.1.10': 'ifInOctets',
            '1.3.6.1.2.1.2.2.1.16': 'ifOutOctets',
            '1.3.6.1.2.1.10.7.2.1.19' : 'duplex'
        }

        results = {key: {} for key in oids.values()}
        
        for oid, attr in oids.items():
            try:
                # Create the SNMP query for each OID
                g = nextCmd(
                        self.engine,
                        self.community_data if self.version in ['v1', 'v2c'] else self.user_data,
                        self.target,
                        self.context,
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False
                )

                # Loop through responses and collect data
                for errorIndication, errorStatus, errorIndex, varBinds in g:
                    if errorIndication:
                        logging.error(f"SNMP error fetching {attr} for OID {oid}: {errorIndication}")
                        break
                    if errorStatus:
                        logging.error(f"SNMP error status {errorStatus.prettyPrint()} on {attr} (OID {oid})")
                        break

                    # Extract and store the result by index
                    for varBind in varBinds:
                        index = varBind[0].prettyPrint().split('.')[-1]
                        results[attr][index] = str(varBind[1].prettyPrint())

            except Exception as e:
                # Log and continue if an exception occurs
                logging.error(f"Exception fetching {attr} for OID {oid}: {e}")
                continue

        # Create Interface objects from the gathered data
        interfaces = []
        for ifIndex in sorted(results['ifIndex'].keys()):
            interfaces.append(Interface(
                ifIndex=results['ifIndex'].get(ifIndex, ''),
                ifDescr=results['ifDescr'].get(ifIndex, ''),
                ifType=results['ifType'].get(ifIndex, ''),
                ifSpeed=results['ifSpeed'].get(ifIndex, ''),
                ifPhysicalAddress=results['ifPhysicalAddress'].get(ifIndex, ''),
                ifAdminStatus=results['ifAdminStatus'].get(ifIndex, ''),
                ifOperStatus=results['ifOperStatus'].get(ifIndex, ''),
                ifInOctets=results['ifInOctets'].get(ifIndex, ''),
                ifOutOctets=results['ifOutOctets'].get(ifIndex, ''),
                duplex=results['duplex'].get(ifIndex, '')
            ))

        return interfaces

    def get_device_details(self) -> Device:
        oids = {
            '1.3.6.1.2.1.1.1.0': 'sysDescr',
            '1.3.6.1.2.1.1.2.0': 'sysObjectID',
            '1.3.6.1.2.1.1.3.0': 'sysUptime',
            '1.3.6.1.2.1.1.4.0': 'sysContact',
            '1.3.6.1.2.1.1.5.0': 'sysName',
            '1.3.6.1.2.1.1.6.0': 'sysLocation',
            '1.3.6.1.4.1.9.9.13.1.4.1.3.0':'fanSpeed',
            '1.3.6.1.4.1.9.9.109.1.1.1.1.6.0' : 'cpu',
            '1.3.6.1.4.1.9.2.1.8.0' : 'memory',
            '1.3.6.1.4.1.9.5.1.2.19.0' : 'serial_no'
        }
        device_info = {}
        for oid, attr in oids.items():
            g = getCmd(
                self.engine,
                self.community_data if self.version in ['v1', 'v2c'] else self.user_data,
                self.target,
                self.context,
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(g)
            if errorIndication or errorStatus:
                logging.error(f"Error fetching {attr}: {errorIndication or errorStatus}")
                device_info[attr] = ''
                continue
            for varBind in varBinds:
                if str(varBind[1].prettyPrint()) == 'No Such Object currently exists at this OID':
                    device_info[attr] = ''
                else:
                    device_info[attr] = str(varBind[1].prettyPrint())
        print(device_info)
        return Device(**device_info)

    def get_all_hosts(self) -> List[Host]:
        mac_table = self.get_mac_address_table()
        all_hosts = []

        for mac_address, port_number in mac_table.items():
            all_hosts.append(Host(macAddress=mac_address, portNumber=port_number))

        return all_hosts

    def get_mac_address_table(self) -> Dict[str, int]:
        mac_table = {}
        mac_oid = '1.3.6.1.2.1.17.4.3.1.1' 
        port_oid = '1.3.6.1.2.1.17.4.3.1.2' 

        # logging.info(f"Fetching MAC address table using OID {mac_oid}")

        
        mac_entries = self._fetch_oid(mac_oid)
        no_of_mac = len(mac_entries)
        logging.info(f"Number of MAC entries: {no_of_mac}")
        port_entries = self._fetch_oid(port_oid)
        no_of_port = len(port_entries)
        logging.info(f"Number of PORT entries: {no_of_port}")

        try:
            for mac_value, port_value in zip(mac_entries, port_entries):
                mac_address = self._oid_to_mac(mac_value)
                try:
                    port_number = int(port_value)
                except ValueError:
                    logging.warning(f"Invalid port number fetched: {port_value}")
                    continue
                if not mac_address:
                    logging.warning(f"Invalid MAC address fetched: {mac_value}")
                else:
                    # logging.info(f"MAC address {mac_address} found on port {port_number}")
                    mac_table[mac_address] = port_number
        except Exception as e:
            logging.error(f"Error fetching MAC address table: {e}")
            return {}
       
        return mac_table

    def _fetch_oid(self, oid: str) -> List[str]:
        results = []
        g = nextCmd(
            self.engine,
            self.community_data if self.version in ['v1', 'v2c'] else self.user_data,
            self.target,
            self.context,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        )
        for errorIndication, errorStatus, errorIndex, varBinds in g:
            if errorIndication or errorStatus:
                logging.error(f"Error fetching OID {oid}: {errorIndication or errorStatus}")
                break
            for varBind in varBinds:
                value = str(varBind[1].prettyPrint())
                # logging.debug(f"Fetched OID {varBind[0].prettyPrint()} with value {value}")
                results.append(value)
        return results

    def _oid_to_mac(self, oid: str) -> str:
        try:
            mac_address = oid.split('.')[-6:]
            return ':'.join([f'{int(b, 16):02X}' for b in mac_address])
        except Exception as e:
            logging.error(f"Error converting OID to MAC address: {e}")
            return ""
        
    def getdata(self, oid):
        """Fetches the value of a specific OID"""
        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                self.engine,
                self.community_data if self.version in ['v1', 'v2c'] else self.user_data,
                self.target,
                self.context,
                ObjectType(ObjectIdentity(oid))
            )
        )

        if error_indication:
            raise Exception(f"Error: {error_indication}")
        elif error_status:
            raise Exception(f"Error: {error_status.prettyPrint()}")
        else:
            return var_binds[0][1]  
            
    def walk(self, oid):
        """Performs an SNMP walk operation for a given OID"""
        values = []
        for (error_indication, error_status, error_index, var_binds) in nextCmd(
                self.engine,
                self.community_data if self.version in ['v1', 'v2c'] else self.user_data,
                self.target,
                self.context,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False  # Walk OIDs only within subtree
        ):
            if error_indication:
                raise Exception(f"Error: {error_indication}")
            elif error_status:
                raise Exception(f"Error: {error_status.prettyPrint()}")
            else:
                for var_bind in var_binds:
                    values.append(var_bind[1])  # Collect all OID values
        return values

    # No value found, return False
    def fetch_snmp_if_mib(self) -> bool:
        oid = '1.3.6.1.2.1.1.1.0'  # sysDescr
        
        # Create an SNMP GET request to fetch the OID value
        g = getCmd(
            self.engine,
            self.community_data if self.version in ['v1', 'v2c'] else self.user_data,
            self.target,
            self.context,
            ObjectType(ObjectIdentity(oid))
        )

        error_indication, error_status, error_index, var_binds = next(g)

        # Handle errors
        if error_indication:
            logging.error(f"Error fetching sysDescr: {error_indication}")
            return False
        elif error_status:
            logging.error(f"Error Status: {error_status.prettyPrint()}")
            return False
        else:
            # Check if any value was returned
            for var_bind in var_binds:
                # Return True if the value exists, regardless of its content
                if var_bind[1]:
                    return True  # Value exists, return True

        return False  # No value found, return False
