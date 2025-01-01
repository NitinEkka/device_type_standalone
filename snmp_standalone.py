from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, UsmUserData,
    usmHMACMD5AuthProtocol, usmDESPrivProtocol
)
import sys

class SNMPClient:
    def __init__(self, version, ip, port=161, community=None, user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None):
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
            return var_binds[0][1]  # Return the value of the OID

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

def main():
    version = input("Enter SNMP version (v1/v2c/v3): ").strip()
    ip = input("Enter device IP address: ").strip()
    port = int(input("Enter SNMP port (default 161): ").strip() or 161)
    
    community = None
    user = None
    auth_key = None
    priv_key = None
    auth_protocol = None
    priv_protocol = None

    if version in ['v1', 'v2c']:
        community = input("Enter SNMP community: ").strip()
    elif version == 'v3':
        user = input("Enter SNMPv3 username: ").strip()
        auth_key = input("Enter SNMPv3 auth key (if any): ").strip() or None
        priv_key = input("Enter SNMPv3 priv key (if any): ").strip() or None

    client = SNMPClient(
        version=version, ip=ip, port=port, community=community, 
        user=user, auth_key=auth_key, priv_key=priv_key,
        auth_protocol=auth_protocol, priv_protocol=priv_protocol
    )
    client.connect()

    oid = input("Enter OID for SNMP GET (or 'walk' for SNMP WALK): ").strip()

    if oid.lower() == 'walk':
        base_oid = input("Enter base OID for SNMP WALK: ").strip()
        values = client.walk(base_oid)
        for value in values:
            print(f"Walk result: {value}")
    else:
        result = client.getdata(oid)
        print(f"SNMP GET result: {result}")

if __name__ == "__main__":
    main()
