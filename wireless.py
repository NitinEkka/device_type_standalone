from connection import connect, disconnect
from sqlalchemy import text
from tools.ap_manager import APManager
from tools.wireless_tools import (
    upsert_multiple_wireless_devices,
    upsert_wireless_configured_ssid,
    upsert_wireless_discovered_ssid,
    update_hosts_ssid
)
from datetime import datetime
import time
from log_helper import log_message

def fetch_online_host(connection):
    try:
        query = """
            SELECT
                hi.ip,
                h.mac,
                h.ncm_conf,
                h.final_device_type,
                CASE
                    WHEN COUNT(sdt.device_type_id) = 0 THEN NULL
                    ELSE JSONB_BUILD_OBJECT(
                        'device_type_id', MAX(COALESCE(sdt.device_type_id, 0)),
                        'device_name', MAX(COALESCE(sdt.device_name, '')),
                        'category', MAX(COALESCE(sdt.category, '')),
                        'ap_model', MAX(COALESCE(sdt.ap_model, ''))
                    )
                END AS snmp_device_type
            FROM
                hosts_view h
            LEFT JOIN
                host_ip hi ON hi.mac = h.mac
            LEFT JOIN
                snmp_device_type AS sdt ON sdt.device_type_id = h.snmp_device
            WHERE
                hi.status = 1
                AND h.is_ncm = TRUE
                AND h.ncm_conf IS NOT NULL
                AND h.snmp_device IS NOT NULL
                AND hi.mac NOT IN (SELECT DISTINCT mac FROM networks)
                AND UPPER(h.final_device_type) IN ('ACCESSPOINT', 'ACCESSCONTROLLER')
            GROUP BY
                hi.ip,
                h.mac,
                h.ncm_conf,
                h.final_device_type;
        """
        rows = connection.execute(text(query)).fetchall()
        return [(row[0], row[1], row[2], row[3], row[4]) for row in rows]
    except Exception as e:
        log_message("ERROR","wireless",f"Error fetching data from host_view: {e}")
        return []

def bulk_insert_wireless_association(connection, data):

    if not data:
        log_message("ERROR","wireless","No data provided for insertion.")
        return

    insert_association_query = f"""
        INSERT INTO wireless_association (host_mac, ap_mac, host_ip, controller_mac, ssid)
        VALUES (:host_mac, :ap_mac, :host_ip, :controller_mac, :ssid);
    """
    
    try:
        # Execute bulk insert
        connection.execute(text(insert_association_query), data)
        connection.commit()
        log_message("INFO","wireless",f"Successfully inserted {len(data)} records into wireless_association.")
    except Exception as e:
        log_message("ERROR","wireless","An error occurred during the bulk insert:", str(e))
        connection.rollback()

def delete_old_data(connection, mac):
    """Delete old data related to the given MAC address from tables."""
    delete_queries = {
        "wireless_details": "DELETE FROM wireless_details WHERE controller_id = :mac",
        "wireless_association": "DELETE FROM wireless_association WHERE controller_mac = :mac",
        "wireless_configured_ssid": "DELETE FROM wireless_configured_ssid WHERE mac = :mac"
    }
    
    for table, query in delete_queries.items():
        connection.execute(text(query), {"mac": mac})
        connection.commit()
        log_message("INFO","wireless",f"OLDER DATA FOR MAC {mac} DELETED in {table}")

def process_common_methods(ap, connection, mac ,ip, ac):
    try:
        print("AC", ac)
        if ac:
            ap_details = ap.getAps()
        else:
            ap_details = [{
                'ap_mac' : mac,
                'supported_security': '',
                'supported_band': "",
                'controller_id': mac,
                'created_at': datetime.now(),
                'modified_at': datetime.now(),
                'name' : '-'
            }]
        wireless_details_array = []

        # Delete older data for the given controller MAC from multiple tables
        delete_old_data(connection, mac)
        print("ALL APs", ap_details)

        for ap_instance in ap_details:
            wireless_details = {
                'mac': ap_instance["ap_mac"].replace("-", ""),
                'supported_security': '',
                'supported_band': "",
                'controller_id': mac,
                'created_at': datetime.now(),
                'modified_at': datetime.now(),
                'name' : ap_instance["name"]
            }
            wireless_details_array.append(wireless_details)
        
        if ac == True:
            wireless_ac_detail = {
                'mac': mac,
                'supported_security': '',
                'supported_band': "",
                'controller_id': mac,
                'created_at': datetime.now(),
                'modified_at': datetime.now(),
                'name' : mac
            }
            wireless_details_array.append(wireless_ac_detail)

        print("WIRELESS DETAILS ARRAY", wireless_details_array)

        upsert_multiple_wireless_devices(wireless_details_array, connection)

        all_hosts_with_ssid = ap.gethosts()
        # update all these hosts in wireless_association
        print("ALL HOSTS", all_hosts_with_ssid)

        wireless_association_array = []

        for host_details in all_hosts_with_ssid:
            wireless_association_data = {
                "host_mac" : host_details["host_mac"].replace("-", ""),
                "ap_mac" : host_details["ap_mac"].replace("-", ""),
                "host_ip" : host_details["host_ip"],
                "controller_mac" : mac,
                "ssid" : host_details["ssid"],
            }
            wireless_association_array.append(wireless_association_data)
            update_hosts_ssid(host_details["ssid"], host_details["host_mac"].replace("-", ""),host_details["ap_mac"].replace("-", ""), connection)
        print("WIRELESS ASSO ARRAY", wireless_association_array)

        bulk_insert_wireless_association(connection, wireless_association_array)

        if not ac:
            print("NOT AC")
            upsert_wireless_configured_ssid(ap.get_configured_ssid(mac), connection)
            upsert_wireless_discovered_ssid(ap.get_discovered_ssid(mac), connection)
        else:
            upsert_wireless_configured_ssid(ap.get_configured_ssid(), connection)
            upsert_wireless_discovered_ssid(ap.get_discovered_ssid(), connection)
    except Exception as e:
        log_message("ERROR","wireless",f"Error processing common methods: {e}")

def main(connection):
    try: 
        
        ap_model = "cisco"
        username = 'Cisco'
        password = 'Cisco'
        ip = '10.255.254.6'
        port = '23'
        protocol = 'telnet'
        device_type = 'ACCESSPOINT'
        mac = 'fjjsdMsnXjog'

        if all([ap_model, username, password, ip, port, protocol, device_type]):
            ap_manager = APManager()
            try:
                ap = ap_manager.create_ap(ap_model, username, password, ip, port, protocol)
            except Exception:
                log_message("ERROR","wireless",f"Unsupported AP model: {ap_model}")
                

            try:
                log_message("INFO","wireless",f"Connecting to {ap_model} AP at {ip} via {protocol}...")
                ap.connect()
                if device_type == 'ACCESSCONTROLLER':

                    process_common_methods(ap, connection, mac,ip, ac=True)
                    
                else:
                    process_common_methods(ap, connection, mac,ip, ac=False)
                
            except Exception as e:
                log_message("ERROR","wireless",f"Error during AP connection or data handling: {e}")
        else:
            missing = {
                "model": ap_model, "username": username, "password": password,
                "ip": ip, "port": port, "protocol": protocol, "device_type": device_type
            }
            log_message("ERROR","wireless",f"Missing values: {', '.join(f'{k}: {v}' for k, v in missing.items() if not v)}")

    except Exception as e:
        log_message("ERROR","wireless",f"An unexpected error occurred in main: {e}")

def operate():
    while True:
        try:
            connection = connect()
            main(connection)  
        except Exception as e:
            log_message("ERROR","wireless",f"Failed to connect to the database: {e}")  
            
        time.sleep(60) 

operate()
