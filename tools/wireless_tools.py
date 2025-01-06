from datetime import datetime
from sqlalchemy import text
from log_helper import log_message

def upsert_multiple_wireless_devices(hosts, connection):
    try:
        # Build the bulk insert query
        query = """
        INSERT INTO wireless_details (mac, supported_security, supported_band, controller_id, created_at, modified_at, name)
        VALUES
        """ + ", ".join(
            f"(:mac_{i}, :supported_security_{i}, :supported_band_{i}, :controller_id_{i}, :created_at_{i}, :modified_at_{i}, :name_{i})"
            for i in range(len(hosts))
        ) + """
        ON CONFLICT (mac)
        DO UPDATE SET
            supported_security = EXCLUDED.supported_security,
            supported_band = EXCLUDED.supported_band,
            controller_id = EXCLUDED.controller_id,
            name = EXCLUDED.name,
            modified_at = EXCLUDED.modified_at;
        """

        # Prepare the parameters for the query
        params = {}
        for i, host in enumerate(hosts):
            params.update({
                f'mac_{i}': host['mac'],
                f'supported_security_{i}': host['supported_security'],
                f'supported_band_{i}': host['supported_band'],
                f'controller_id_{i}': host['controller_id'],
                f'created_at_{i}': host.get('created_at', datetime.now()),  # Use current time if not provided
                f'modified_at_{i}': datetime.now(),  # Always update modified_at to current time
                f'name_{i}': host['name']  # Add the name field to params
            })

        # Execute the query with all parameters
        connection.execute(text(query), params)
        connection.commit()
        return True
    except Exception as e:
        log_message("ERROR","scanner_tool",f'Error during bulk upserting wireless devices -> {e}')
        return False

def upsert_wireless_configured_ssid(all_hosts, connection):
    try:
        # Create a set to store unique ap_mac values for deletion
        unique_mac_set = set(host['ap_mac'].replace("-", "") for host in all_hosts)

        # Build the bulk delete query
        if unique_mac_set:
            delete_query = f"""
            DELETE FROM wireless_configured_ssid
            WHERE mac IN ({', '.join(f':mac_{i}' for i in range(len(unique_mac_set)))});
            """

            # Prepare parameters for the delete query
            delete_params = {f'mac_{i}': mac for i, mac in enumerate(unique_mac_set)}

            # Execute the delete query
            connection.execute(text(delete_query), delete_params)
            connection.commit()

        # Build the bulk insert query with unique entries
        query = """
        INSERT INTO wireless_configured_ssid (bssid, mac, ssid, security_type, created_at, modified_at)
        VALUES
        """ + ", ".join(
            f"(:bssid_{i}, :mac_{i}, :ssid_{i}, :security_type_{i}, :created_at_{i}, :modified_at_{i})"
            for i in range(len(all_hosts))
        ) + """
        ON CONFLICT (bssid)
        DO UPDATE SET
            ssid = EXCLUDED.ssid,
            security_type = EXCLUDED.security_type,
            modified_at = EXCLUDED.modified_at;
        """

        # Prepare the parameters for the query
        params = {}
        for i, host in enumerate(all_hosts):
            params.update({
                f'bssid_{i}': host['bssid'].replace("-", "").lower(),
                f'mac_{i}': host['ap_mac'].replace("-", ""),
                f'ssid_{i}': host['ssid'],
                f'security_type_{i}': host['security_type'],
                f'created_at_{i}': datetime.now(),  # Insert time
                f'modified_at_{i}': datetime.now()  # Updated each time
            })

        # Execute the insert query with all parameters
        connection.execute(text(query), params)
        connection.commit()
        return True
    except Exception as e:
        log_message("ERROR","scanner_tool",f'Error during bulk upserting wireless configured SSID -> {e}')
        return False


def upsert_wireless_discovered_ssid(hosts_all_data, connection):
    try:
        # Create a set to store unique ap_mac values for deletion
        unique_mac_set = set(host['ap_mac'].replace("-", "") for host in hosts_all_data)

        # Build the bulk delete query
        if unique_mac_set:
            delete_query = f"""
            DELETE FROM wireless_discovered_ssid
            WHERE mac IN ({', '.join(f':mac_{i}' for i in range(len(unique_mac_set)))});
            """

            # Prepare parameters for the delete query
            delete_params = {f'mac_{i}': mac for i, mac in enumerate(unique_mac_set)}

            # Execute the delete query
            connection.execute(text(delete_query), delete_params)
            connection.commit()

        query = """
        INSERT INTO wireless_discovered_ssid (bssid, mac, ssid, security_type, created_at, modified_at)
        VALUES
        """ + ", ".join(
            f"(:bssid_{i},:mac_{i}, :ssid_{i}, :security_type_{i}, :created_at_{i}, :modified_at_{i})"
            for i in range(len(hosts_all_data))
        ) + """
        ON CONFLICT (bssid)
        DO UPDATE SET
            ssid = EXCLUDED.ssid,
            security_type = EXCLUDED.security_type,
            modified_at = EXCLUDED.modified_at;
        """

        # Prepare the parameters for the query
        params = {}
        for i, host in enumerate(hosts_all_data):
            params.update({
                f'bssid_{i}': host['bssid'].replace("-", "").lower(),
                f'mac_{i}': host['ap_mac'].replace("-", ""),
                f'ssid_{i}': host['ssid'],
                f'security_type_{i}': host['security_type'],
                f'created_at_{i}': datetime.now(),  # Insert timestamp
                f'modified_at_{i}': datetime.now(),  # Always update on conflict
            })

        # Execute the query with all parameters
        connection.execute(text(query), params)
        connection.commit()
        return True
    except Exception as e:
        log_message("ERROR","scanner_tool",f'Error during bulk upserting wireless discovered SSID -> {e}')
        return False

def get_configured_ssid(AP):
    ssids = []
    return (ssids)

def get_discovered_ssid(AP):
    ssids = []
    return (ssids)

def update_hosts_ssid(ssid, mac,ap_mac, connection):
    try:
        update_ssid_query = """
            UPDATE hosts
            SET ssid = :ssid,
                access_point_id = :access_point_id
            WHERE mac = :mac;
        """
        # Execute the query with parameters
        connection.execute(text(update_ssid_query), {"ssid": ssid, "mac": mac, "access_point_id" : ap_mac})
        connection.commit()
        return True
    except Exception as e:
        log_message("ERROR","scanner_tool",f'Error during updating hosts SSID -> {e}')
        return False