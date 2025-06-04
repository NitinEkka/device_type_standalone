from meshcentral_client import MeshCentralClient
from datetime import datetime, timedelta, timezone
from sqlalchemy import text
import json
import re
import ast

class MeshCentralAdaptor:
    def __init__(self, client, connection, node_id, device_id):
        self.client = client
        self.connection = connection
        self.node_id = node_id
        self.ws_url = "wss://192.168.15.15:8086/control.ashx"
        self.origin = "https://192.168.30.22"
        self.device_id = device_id
        # self.memory_cache = {}
        # self.client.connect()

    # def get_and_set_all_data(self) -> dict:
    #     """
    #     Takes a list of property names and runs corresponding get_ and set_ methods
    #     with real_time=True for get functions. Returns a dict with property name as key 
    #     and True/False as value depending on success or failure of get/set operations.
    #     """
    #     results = {}

    #     # Add all property names here
    #     # properties = [
    #     #     "process", "cpuinfo", "programs", "cpustat", "services", "diskinfo",
    #     #     "netinfo", "logical_drives", "memory_devices", "memory_stat",
    #     #     "pci_devices", "platform_info", "system_info", "users", "wmi_bios",
    #     #     "nt_domain", "os_version", "interface_addresses"
    #     # ]

    #     properties = ["process"]

    #     print("ADAPTOR CLIENT : ", self.client)

    #     for prop in properties:
    #         get_fn_name = f"get_{prop}"
    #         set_fn_name = f"set_{prop}"

    #         get_fn = getattr(self, get_fn_name, None)
    #         set_fn = getattr(self, set_fn_name, None)

    #         if not callable(get_fn) or not callable(set_fn):
    #             print(f"[WARNING] Missing get/set for '{prop}'")
    #             results[prop] = False
    #             continue

    #         try:
    #             # Pass real_time=True to all get_ functions
    #             data = get_fn(real_time=True)
    #             if data is not None:
    #                 set_fn(data)
    #                 results[prop] = True
    #             else:
    #                 print(f"[INFO] No data returned for '{prop}'")
    #                 results[prop] = False
    #         except Exception as e:
    #             print(f"[ERROR] Failed to process '{prop}': {e}")
    #             results[prop] = False

    #     return results

    def get_and_set_all_data(self) -> dict:
        """
        Runs get_ and set_ methods for each property with real_time=True.
        Returns a dict:
        {
            "status": {property_name: True/False},
            "data": {property_name: <get_output>}
        }
        """
        # properties = [
        #     "process", "cpuinfo", "programs", "cpustat", "services", "diskinfo",
        #     "interface_details", "logical_drives", "memory_devices", "memory_stat",
        #     "pci_devices", "platform_info", "system_info", "users", "wmi_bios",
        #     "nt_domain", "os_version", "interface_addresses", "antivirus"
        # ]

        properties = ["nt_domain"]

        status = {}
        data = {}

        for prop in properties:
            get_fn_name = f"get_{prop}"
            set_fn_name = f"set_{prop}"

            get_fn = getattr(self, get_fn_name, None)
            set_fn = getattr(self, set_fn_name, None)

            if not callable(get_fn) or not callable(set_fn):
                print(f"[WARNING] Missing get/set for '{prop}'")
                status[prop] = False
                continue

            try:
                result = get_fn(real_time=True)
                if result is not None:
                    set_fn(result)
                    status[prop] = True
                    data[prop] = result
                else:
                    print(f"[INFO] No data returned for '{prop}'")
                    status[prop] = False
            except Exception as e:
                print(f"[ERROR] Failed to process '{prop}': {e}")
                status[prop] = False

        return {
            "status": status,
            "data": data
        }

    def get_process(self, real_time=True, cache_data=None):
        property_name = "process"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "ps"
            }
            print("📤 PROCESS COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 PROCESS RESPONSE:", output)

            return output
        else:
            print("📦 PROCESS RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]

    def set_process(self, process_string):
        print("Raw process string received")

        lines = process_string.strip().split("\r\n")

        if len(lines) <= 1:
            print("No process data to parse.")
            return

        # Skip header and split lines
        process_entries = []
        for line in lines[1:]:
            parts = [p.strip() for p in line.split(",")]

            if len(parts) < 2:
                print(f"Invalid line (less than 2 parts): {line}")
                return  # Abort if any line is invalid

            pid = parts[0]
            name = parts[-1]
            pgroup = parts[1] if len(parts) == 3 else None

            process_entries.append({
                "pid": pid,
                "pgroup": pgroup,
                "name": name,
                "device_id": self.device_id
            })

        # All entries are valid, proceed
        try:
            # Step 1: Delete existing entries for the device
            delete_query = text("DELETE FROM processes WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})
            self.connection.commit()

            # Step 2: Insert new entries
            for entry in process_entries:
                def escape(val):
                    return val.replace("'", "''") if val is not None else None

                columns = ", ".join(entry.keys())
                values = ", ".join([f"'{escape(v)}'" if v is not None else "NULL" for v in entry.values()])

                insert_query = f"""INSERT INTO processes ({columns}) VALUES ({values})"""
                self.connection.execute(text(insert_query))

            self.connection.commit()
            print("Process data updated successfully.")

        except Exception as e:
            self.connection.rollback()
            print(f"Database error: {e}")


    def get_cpuinfo(self, real_time=True, cache_data=None):
        property_name = "cpuinfo"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 CPUINFO COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 CPUINFO RESPONSE:", output)

            return output
        else:
            print("📦 CPUINFO RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]

    # def set_cpuinfo(self, cpuinfo):
    #     try:
    #         # Convert string to JSON object
    #         if isinstance(cpuinfo, str):
    #             cpuinfo = json.loads(cpuinfo)

    #         # Safely extract CPU list
    #         cpu_list = cpuinfo.get("hardware", {}).get("windows", {}).get("cpu", [])
    #         if not isinstance(cpu_list, list) or not cpu_list:
    #             return  # Exit if list is empty or invalid

    #         valid_entries = []
    #         for cpu in cpu_list:
    #             if not isinstance(cpu, dict):
    #                 continue

    #             required_fields = ["Name", "DeviceID", "Manufacturer", "MaxClockSpeed", "SocketDesignation"]
    #             if not all(cpu.get(field) for field in required_fields):
    #                 continue  # Skip incomplete entries

    #             entry = {
    #                 "device_id": self.device_id,
    #                 "model": cpu["Name"],
    #                 "cpu_device_id": cpu["DeviceID"],
    #                 "manufacturer": cpu["Manufacturer"] + " " + cpu.get("Caption", ""),
    #                 "max_clock_speed": cpu["MaxClockSpeed"],
    #                 "socket_designation": cpu["SocketDesignation"]
    #             }
    #             valid_entries.append(entry)

    #         if not valid_entries:
    #             return

    #         # Clear existing CPU info for the device
    #         delete_query = text("DELETE FROM cpu_info WHERE device_id = :device_id")
    #         self.connection.execute(delete_query, {"device_id": self.device_id})

    #         # Insert new CPU info
    #         for entry in valid_entries:
    #             columns = ', '.join(entry.keys())
    #             placeholders = ', '.join([f":{k}" for k in entry])
    #             insert_query = text(f"INSERT INTO cpu_info ({columns}) VALUES ({placeholders})")
    #             self.connection.execute(insert_query, entry)

    #         self.connection.commit()

    #     except json.JSONDecodeError:
    #         print("Invalid JSON format in cpuinfo string")
    #     except Exception as e:
    #         print(f"Failed to set CPU info: {e}")

    def set_cpuinfo(self, cpuinfo):
        try:
            # Convert string to JSON object if needed
            if isinstance(cpuinfo, str):
                cpuinfo = json.loads(cpuinfo)

            # Extract the appropriate CPU info source
            windows_cpu_list = cpuinfo.get("hardware", {}).get("windows", {}).get("cpu", [])
            linux_cpu_info = cpuinfo.get("hardware", {}).get("linux", {})

            valid_entries = []

            # Handle Windows CPU list
            if isinstance(windows_cpu_list, list) and windows_cpu_list:
                for cpu in windows_cpu_list:
                    if not isinstance(cpu, dict):
                        continue

                    required_fields = ["Name", "DeviceID", "Manufacturer", "MaxClockSpeed", "SocketDesignation"]
                    if not all(cpu.get(field) for field in required_fields):
                        continue  # Skip incomplete entries

                    entry = {
                        "device_id": self.device_id,
                        "model": cpu["Name"],
                        "cpu_device_id": cpu["DeviceID"],
                        "manufacturer": cpu["Manufacturer"] + " " + cpu.get("Caption", ""),
                        "max_clock_speed": cpu["MaxClockSpeed"],
                        "socket_designation": cpu["SocketDesignation"]
                    }
                    valid_entries.append(entry)

            # Handle Linux CPU info
            elif isinstance(linux_cpu_info, dict) and linux_cpu_info.get("product_name") and linux_cpu_info.get("chassis_vendor"):
                entry = {
                    "device_id": self.device_id,
                    "model": linux_cpu_info.get("product_name"),
                    "cpu_device_id": "",  
                    "manufacturer": linux_cpu_info.get("chassis_vendor"),
                    "max_clock_speed": None,  # Not provided in Linux data
                    "socket_designation": None
                }
                valid_entries.append(entry)

            if not valid_entries:
                return  # No valid entries to insert

            # Clear existing CPU info for the device
            delete_query = text("DELETE FROM cpu_info WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert new CPU info
            for entry in valid_entries:
                columns = ', '.join(entry.keys())
                placeholders = ', '.join([f":{k}" for k in entry])
                insert_query = text(f"INSERT INTO cpu_info ({columns}) VALUES ({placeholders})")
                self.connection.execute(insert_query, entry)

            self.connection.commit()

        except json.JSONDecodeError:
            print("Invalid JSON format in cpuinfo string")
        except Exception as e:
            print(f"Failed to set CPU info: {e}")

    def get_cpustat(self, real_time=True, cache_data=None):
        property_name = "cpustat"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "cpuinfo"
            }
            print("📤 CPUSTAT COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 CPUSTAT RESPONSE:", output)

            return output
        else:
            print("📦 CPUSTAT RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]

    def set_cpustat(self, cpu_usage_str):
        try:
            # Convert string to JSON
            cpu_usage = json.loads(cpu_usage_str)

            # Extract percentConsumed
            percent_consumed = cpu_usage.get("memory", {}).get("percentConsumed")
            if percent_consumed is None or not isinstance(percent_consumed, (int, float)):
                print("Invalid or missing percentConsumed, skipping insert")
                return

            # Simple insert with no conflict check
            insert_query = text("""
                INSERT INTO cpu_stat (device_id, cpu_usage)
                VALUES (:device_id, :cpu_usage)
            """)
            self.connection.execute(insert_query, {
                "device_id": self.device_id,
                "cpu_usage": percent_consumed
            })
            self.connection.commit()
            print("Inserted cpu_usage successfully.")

        except Exception as e:
            print(f"Error in set_cpustat: {e}")

    def get_programs(self, real_time=True, cache_data=None):
        property_name = "programs"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "installedapps"
            }
            print("📤 PROGRAMS COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 PROGRAMS RESPONSE:", output)

            return output
        else:
            print("📦 PROGRAMS RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]

    def set_programs(self, programs):
        try:
            # Convert string JSON to Python list, if needed
            if isinstance(programs, str):
                programs = json.loads(programs)
            
            # If not a list after loading, just exit
            if not isinstance(programs, list):
                return

            valid_programs = []
            for prog in programs:
                if isinstance(prog, dict):
                    # Count non-empty fields
                    non_empty_values = [v for v in prog.values() if v]
                    if len(non_empty_values) >= 2:
                        # Build data dict including device_id
                        data = {
                            "device_id": self.device_id,
                            "name": prog.get("name", ""),
                            "version": prog.get("version", ""),
                            "install_location": prog.get("location", ""),
                            "install_date": prog.get("installdate", "")
                        }
                        valid_programs.append(data)

            if not valid_programs:
                return

            # Delete old entries for this device_id
            delete_query = text("DELETE FROM programs WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert all valid programs
            insert_query = text("""
                INSERT INTO programs (device_id, name, version, install_location, install_date)
                VALUES (:device_id, :name, :version, :install_location, :install_date)
            """)
            for program in valid_programs:
                self.connection.execute(insert_query, program)

            self.connection.commit()

        except Exception as e:
            print(f"Error in set_programs: {e}")

    def get_services(self, real_time=True, cache_data=None):
        property_name = "services"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "type": "services",
                "nodeid": self.node_id
            }
            print("📤 SERVICES COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 SERVICES RESPONSE:", output)

            return output
        else:
            print("📦 SERVICES RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    # def set_services(self, services):
    #     # Convert string to list of dicts if needed
    #     if isinstance(services, str):
    #         try:
    #             services = json.loads(services)
    #         except json.JSONDecodeError:
    #             print("Invalid JSON format")
    #             return

    #     if not isinstance(services, list):
    #         print("Services must be a list of dictionaries")
    #         return

    #     # Delete existing entries for device_id
    #     delete_query = text("DELETE FROM services WHERE device_id = :device_id")
    #     self.connection.execute(delete_query, {"device_id": self.device_id})

    #     for svc in services:
    #         # Validate required keys
    #         if not all(k in svc for k in ["name", "displayName", "status"]):
    #             continue

    #         status = svc.get("status", {})
    #         required_status_keys = [
    #             "isFileSystemDriver", "isKernelDriver", "isSharedProcess",
    #             "isOwnProcess", "isInteractive", "state", "pid"
    #         ]
    #         if not all(k in status for k in required_status_keys):
    #             continue

    #         # Determine service_type
    #         if status["isFileSystemDriver"]:
    #             service_type = "SERVICE_FILE_SYSTEM_DRIVER"
    #         elif status["isKernelDriver"]:
    #             service_type = "SERVICE_KERNEL_DRIVER"
    #         elif status["isOwnProcess"]:
    #             service_type = "SERVICE_WIN32_OWN_PROCESS"
    #         elif status["isSharedProcess"]:
    #             service_type = "SERVICE_WIN32_SHARE_PROCESS"
    #         else:
    #             service_type = "Cannot determine all flags are false"

    #         # Insert into DB
    #         data = {
    #             "device_id": self.device_id,
    #             "name": svc["name"],
    #             "display_name": svc["displayName"],
    #             "status": status["state"],
    #             "pid": status["pid"],
    #             "service_type": service_type
    #         }

    #         insert_query = text(f"""
    #             INSERT INTO services (device_id, name, display_name, status, pid, service_type)
    #             VALUES (:device_id, :name, :display_name, :status, :pid, :service_type)
    #         """)

    #         self.connection.execute(insert_query, data)

    #     self.connection.commit()

    def set_services(self, services):

        # Convert string to list of dicts if needed
        if isinstance(services, str):
            try:
                services = json.loads(services)
            except json.JSONDecodeError:
                print("Invalid JSON format")
                return

        if not isinstance(services, list):
            print("Services must be a list of dictionaries")
            return

        if not services:
            print("No services to process")
            return

        # Delete existing entries for device_id
        delete_query = text("DELETE FROM services WHERE device_id = :device_id")
        self.connection.execute(delete_query, {"device_id": self.device_id})

        first_item = services[0]

        # Determine if this is Windows or Linux format
        is_windows = "status" in first_item and isinstance(first_item["status"], dict)
        is_linux = all(k in first_item for k in ["name", "escname", "serviceType"])

        if is_windows:
            for svc in services:
                # Validate required keys
                if not all(k in svc for k in ["name", "displayName", "status"]):
                    continue

                status = svc.get("status", {})
                required_status_keys = [
                    "isFileSystemDriver", "isKernelDriver", "isSharedProcess",
                    "isOwnProcess", "isInteractive", "state", "pid"
                ]
                if not all(k in status for k in required_status_keys):
                    continue

                # Determine service_type
                if status["isFileSystemDriver"]:
                    service_type = "SERVICE_FILE_SYSTEM_DRIVER"
                elif status["isKernelDriver"]:
                    service_type = "SERVICE_KERNEL_DRIVER"
                elif status["isOwnProcess"]:
                    service_type = "SERVICE_WIN32_OWN_PROCESS"
                elif status["isSharedProcess"]:
                    service_type = "SERVICE_WIN32_SHARE_PROCESS"
                else:
                    service_type = "UNKNOWN"

                data = {
                    "device_id": self.device_id,
                    "name": svc["name"],
                    "display_name": svc["displayName"],
                    "status": status["state"],
                    "pid": status["pid"],
                    "service_type": service_type
                }

                insert_query = text("""
                    INSERT INTO services (device_id, name, display_name, status, pid, service_type)
                    VALUES (:device_id, :name, :display_name, :status, :pid, :service_type)
                """)
                self.connection.execute(insert_query, data)

        elif is_linux:
            for svc in services:
                if not all(k in svc for k in ["name", "escname", "serviceType"]):
                    continue

                data = {
                    "device_id": self.device_id,
                    "name": svc["name"],
                    "display_name": svc["escname"],
                    "status": "",  # Linux payload does not provide status
                    "pid": None,   # Linux payload does not provide pid
                    "service_type": svc["serviceType"]
                }

                insert_query = text("""
                    INSERT INTO services (device_id, name, display_name, status, pid, service_type)
                    VALUES (:device_id, :name, :display_name, :status, :pid, :service_type)
                """)
                self.connection.execute(insert_query, data)

        else:
            print("Unrecognized service payload structure")
            return

        self.connection.commit()

    def get_diskinfo(self, real_time=True, cache_data=None):
        property_name = "diskinfo"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 DISKINFO COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 DISKINFO RESPONSE:", output)

            return output
        else:
            print("📦 DISKINFO RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    # def set_diskinfo(self, cpuinfo):
    #     try:
    #         # Convert string to JSON object
    #         if isinstance(cpuinfo, str):
    #             cpuinfo = json.loads(cpuinfo)

    #         # Safely extract CPU list
    #         drives_list = cpuinfo.get("hardware", {}).get("windows", {}).get("drives", [])
    #         if not isinstance(drives_list, list) or not drives_list:
    #             return  # Exit if list is empty or invalid

    #         valid_entries = []
    #         for drives in drives_list:
    #             if not isinstance(drives, dict):
    #                 continue

    #             required_fields = ["Caption", "DeviceID", "Model", "Partitions", "Size"]
    #             if not all(drives.get(field) for field in required_fields):
    #                 continue  # Skip incomplete entries

    #             entry = {
    #                 "device_id": self.device_id,
    #                 "disk_size": drives["Size"],
    #                 "partitions": drives["Partitions"],
    #                 "hardware_model": drives["Model"] ,
    #                 "description": drives["Caption"]
    #             }
    #             valid_entries.append(entry)

    #         if not valid_entries:
    #             return

    #         # Clear existing CPU info for the device
    #         delete_query = text("DELETE FROM disk_info WHERE device_id = :device_id")
    #         self.connection.execute(delete_query, {"device_id": self.device_id})

    #         # Insert new CPU info
    #         for entry in valid_entries:
    #             columns = ', '.join(entry.keys())
    #             placeholders = ', '.join([f":{k}" for k in entry])
    #             insert_query = text(f"INSERT INTO disk_info ({columns}) VALUES ({placeholders})")
    #             self.connection.execute(insert_query, entry)

    #         self.connection.commit()

    #     except json.JSONDecodeError:
    #         print("Invalid JSON format in diskinfo string")
    #     except Exception as e:
    #         print(f"Failed to set DISK info: {e}")


    def set_diskinfo(self, cpuinfo):
        try:
            # Convert string to JSON object
            if isinstance(cpuinfo, str):
                cpuinfo = json.loads(cpuinfo)

            valid_entries = []

            # Handle Windows drives
            windows_drives = cpuinfo.get("hardware", {}).get("windows", {}).get("drives", [])
            if isinstance(windows_drives, list):
                for drive in windows_drives:
                    if not isinstance(drive, dict):
                        continue

                    required_fields = ["Caption", "DeviceID", "Model", "Partitions", "Size"]
                    if not all(drive.get(field) for field in required_fields):
                        continue  # Skip incomplete entries

                    entry = {
                        "device_id": self.device_id,
                        "disk_size": drive["Size"],
                        "partitions": drive["Partitions"],
                        "hardware_model": drive["Model"],
                        "description": drive["Caption"]
                    }
                    valid_entries.append(entry)

            # Handle Linux volumes
            linux_volumes = cpuinfo.get("hardware", {}).get("linux", {}).get("volumes", [])
            if isinstance(linux_volumes, list):
                for volume in linux_volumes:
                    if not isinstance(volume, dict):
                        continue

                    required_fields = ["mount_point", "type", "size", "used", "available"]
                    if not all(volume.get(field) for field in required_fields):
                        continue  # Skip incomplete entries

                    entry = {
                        "device_id": self.device_id,
                        "id": volume["mount_point"],
                        "type": volume["type"],
                        "disk_size": volume["size"],
                        "used_disk": volume["used"],
                        "free_disk": volume["available"]
                    }
                    valid_entries.append(entry)

            if not valid_entries:
                return

            # Clear existing disk info for the device
            delete_query = text("DELETE FROM disk_info WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert new disk info
            for entry in valid_entries:
                columns = ', '.join(entry.keys())
                placeholders = ', '.join([f":{k}" for k in entry])
                insert_query = text(f"INSERT INTO disk_info ({columns}) VALUES ({placeholders})")
                self.connection.execute(insert_query, entry)

            self.connection.commit()

        except json.JSONDecodeError:
            print("Invalid JSON format in diskinfo string")
        except Exception as e:
            print(f"Failed to set DISK info: {e}")



    def get_interface_details(self, real_time=True, cache_data=None):
        property_name = "interface_details"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "netinfo"
            }
            print("📤 INTERFACE DETAILS COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 INTERFACE DETAILS RESPONSE:", repr(output))

            return output
        else:
            print("📦 INTERFACE DETAILS RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    

    # def set_interface_details(self, netinfo):
    #     def fix_netinfo_string(s):
    #         # Step 1: Normalize newlines and remove carriage returns
    #         s = s.replace('\r\n', '\n').replace('\r', '\n')

    #         # Step 2: Add double quotes around top-level keys
    #         s = re.sub(r'^(\s*)([A-Za-z0-9 _-]+):', r'\1"\2":', s, flags=re.MULTILINE)

    #         # Step 3: Add double quotes around nested keys (numbers or words)
    #         s = re.sub(r'(\n\s*)(\d+):', r'\1"\2":', s)

    #         # Step 4: Add commas between key-value pairs if missing
    #         s = re.sub(r'("\s*:\s*[^,\{\[\n]+)(\n\s*")', r'\1,\2', s)
    #         s = re.sub(r'(".*?")(\s*:)(".*?")(\s*")', r'\1\2\3,\4', s)  # rare edge case

    #         # Step 5: Add commas between closing braces and next key
    #         s = re.sub(r'(\})\s*(\d+":)', r'\1,\n\2', s)
    #         s = re.sub(r'(\})\s*("[A-Za-z0-9 _-]+":)', r'\1,\n\2', s)

    #         # Step 6: Ensure all object pairs are comma separated
    #         s = re.sub(r'"\s*\n\s*([}\]])', r'",\n\1', s)

    #         # Step 7: Remove extra trailing commas before closing braces
    #         s = re.sub(r',\s*([\]}])', r'\1', s)

    #         return s

    #     try:
    #         if isinstance(netinfo, str):
    #             netinfo = netinfo.strip()
    #             try:
    #                 netinfo_json = json.loads(netinfo)
    #             except json.JSONDecodeError:
    #                 fixed_str = fix_netinfo_string(netinfo)
    #                 netinfo_json = json.loads(fixed_str)
    #         elif isinstance(netinfo, dict):
    #             netinfo_json = netinfo
    #         else:
    #             print("⚠️ netinfo must be a string or dict.")
    #             return

    #         print("✅ Parsed interface details JSON.")

    #         entries = []
    #         for interface, configs in netinfo_json.items():
    #             if not isinstance(configs, dict):
    #                 continue
    #             for _, config in configs.items():
    #                 if not isinstance(config, dict):
    #                     continue

    #                 mac = config.get("mac")
    #                 status = config.get("status")
    #                 iface_type = config.get("type")

    #                 if not mac or not status or not iface_type:
    #                     continue

    #                 entries.append({
    #                     "device_id": self.device_id,
    #                     "interface": interface,
    #                     "type": iface_type,
    #                     "mac": mac,
    #                     "connection_status": status,
    #                 })

    #         if not entries:
    #             print("⚠️ No valid interface entries found.")
    #             return

    #         # Clear previous entries
    #         delete_query = text("DELETE FROM interface_details WHERE device_id = :device_id")
    #         self.connection.execute(delete_query, {"device_id": self.device_id})

    #         # Insert updated entries
    #         for entry in entries:
    #             keys = ', '.join(entry.keys())
    #             vals = ', '.join([f':{k}' for k in entry])
    #             insert = text(f"INSERT INTO interface_details ({keys}) VALUES ({vals})")
    #             self.connection.execute(insert, entry)

    #         self.connection.commit()
    #         print(f"✅ Stored {len(entries)} interfaces for device {self.device_id}")

    #     except json.JSONDecodeError as e:
    #         print(f"❌ Failed to parse netinfo string: {e}")
    #     except Exception as e:
    #         print(f"❌ Unexpected error: {e}")


    def set_interface_details(self, netinfo):
        def fix_netinfo_string(s):
            s = s.replace('\r\n', '\n').replace('\r', '\n')
            s = re.sub(r'^(\s*)([A-Za-z0-9 _-]+):', r'\1"\2":', s, flags=re.MULTILINE)
            s = re.sub(r'(\n\s*)(\d+):', r'\1"\2":', s)
            s = re.sub(r'("\s*:\s*[^,\{\[\n]+)(\n\s*")', r'\1,\2', s)
            s = re.sub(r'(".*?")(\s*:)(".*?")(\s*")', r'\1\2\3,\4', s)
            s = re.sub(r'(\})\s*(\d+":)', r'\1,\n\2', s)
            s = re.sub(r'(\})\s*("[A-Za-z0-9 _-]+":)', r'\1,\n\2', s)
            s = re.sub(r'"\s*\n\s*([}\]])', r'",\n\1', s)
            s = re.sub(r',\s*([\]}])', r'\1', s)
            return s

        try:
            if isinstance(netinfo, str):
                netinfo = netinfo.strip()
                try:
                    netinfo_json = json.loads(netinfo)
                except json.JSONDecodeError:
                    fixed_str = fix_netinfo_string(netinfo)
                    netinfo_json = json.loads(fixed_str)
            elif isinstance(netinfo, dict):
                netinfo_json = netinfo
            else:
                print("⚠️ netinfo must be a string or dict.")
                return

            print("✅ Parsed interface details JSON.")

            entries = []
            for interface, configs in netinfo_json.items():
                if not isinstance(configs, dict):
                    continue

                # Extract only the first word of the interface name
                short_interface = interface.split()[0]

                for _, config in configs.items():
                    if not isinstance(config, dict):
                        continue

                    mac = config.get("mac")
                    status = config.get("status")
                    iface_type = config.get("type")

                    if not mac or not status or not iface_type:
                        continue

                    entries.append({
                        "device_id": self.device_id,
                        "interface": short_interface,
                        "type": iface_type,
                        "mac": mac,
                        "connection_status": status,
                    })

            if not entries:
                print("⚠️ No valid interface entries found.")
                return

            # Clear previous entries
            delete_query = text("DELETE FROM interface_details WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert updated entries
            for entry in entries:
                keys = ', '.join(entry.keys())
                vals = ', '.join([f':{k}' for k in entry])
                insert = text(f"INSERT INTO interface_details ({keys}) VALUES ({vals})")
                self.connection.execute(insert, entry)

            self.connection.commit()
            print(f"✅ Stored {len(entries)} interfaces for device {self.device_id}")

        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse netinfo string: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

    def get_logical_drives(self, real_time=True, cache_data=None):
        property_name = "logical_drives"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "volumes"
            }
            print("📤 LOGICAL DRIVES COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 LOGICAL DRIVES RESPONSE:", output)

            return output
        else:
            print("📦 LOGICAL DRIVES RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    def set_logical_drives(self, volumes_str):
        try:
            volumes_data = json.loads(volumes_str)
        except json.JSONDecodeError as e:
            print(f"Failed to decode volumes JSON string: {e}")
            return

        required_fields = ['Name', 'DriveType', 'Caption', 'FreeSpace', 'Capacity', 'FileSystem']
        valid_volumes = []

        for device_id, volume_info in volumes_data.items():
            if all(field in volume_info for field in required_fields):
                valid_volumes.append({
                    'drive_device_id': volume_info['Name'],
                    'type': volume_info['DriveType'],
                    'description': volume_info['Caption'],
                    'free_space': volume_info['FreeSpace'],
                    'size': volume_info['Capacity'],
                    'file_system': volume_info['FileSystem'],
                    'device_id': self.device_id
                })
            else:
                missing = [f for f in required_fields if f not in volume_info]
                print(f"Skipping volume {device_id} due to missing fields: {missing}")

        if not valid_volumes:
            print("No valid volumes to insert.")
            return

        try:
            # Delete old entries for this device
            delete_query = text("DELETE FROM logical_drives WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})
            self.connection.commit()

            # Insert each record individually with named parameters
            insert_query = text("""
                INSERT INTO logical_drives (
                    drive_device_id,
                    type,
                    description,
                    free_space,
                    size,
                    file_system,
                    device_id
                ) VALUES (
                    :drive_device_id,
                    :type,
                    :description,
                    :free_space,
                    :size,
                    :file_system,
                    :device_id
                )
            """)

            for vol in valid_volumes:
                self.connection.execute(insert_query, vol)
                self.connection.commit()

            print(f"Inserted {len(valid_volumes)} logical drives successfully.")

        except Exception as e:
            print(f"Failed to insert logical drives: {e}")

    def get_memory_devices(self, real_time=True, cache_data=None):
        property_name = "memory_devices"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 MEMORY DEVICES COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 MEMORY DEVICES RESPONSE:", output)

            return output
        else:
            print("📦 MEMORY DEVICES RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    def set_memory_devices(self, memory_devices):
        try:
            # Convert string to JSON object
            if isinstance(memory_devices, str):
                memory_devices = json.loads(memory_devices)
            memory_list = memory_devices.get("hardware", {}).get("windows", {}).get("memory", [])
            if not isinstance(memory_list, list) or not memory_list:
                return
            valid_entries = []
            for memory in memory_list:
                if not isinstance(memory, dict):
                    continue

                required_fields = ["FormFactor", "Capacity", "Manufacturer", "MemoryType", "Name", "Tag", "DeviceLocator"]
                if not all(memory.get(field) for field in required_fields):
                    continue  # Skip incomplete entries

                entry = {
                    "device_id": self.device_id,
                    "asset_tag": memory["Tag"],
                    "form_factor": memory["FormFactor"],
                    "size": int(memory["Capacity"]) // (1024 * 1024),
                    "manufacturer": memory["Manufacturer"],
                    "device_locator" : memory["DeviceLocator"],
                    "memory_type" : memory["MemoryType"],
                    "memory_type_details" : memory["Name"]
                }
                valid_entries.append(entry)
            if not valid_entries:
                return
            # Clear existing CPU info for the device
            delete_query = text("DELETE FROM memory_devices WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert new CPU info
            for entry in valid_entries:
                columns = ', '.join(entry.keys())
                placeholders = ', '.join([f":{k}" for k in entry])
                insert_query = text(f"INSERT INTO memory_devices ({columns}) VALUES ({placeholders})")
                self.connection.execute(insert_query, entry)

            self.connection.commit()
        except json.JSONDecodeError:
            print("Invalid JSON format in memory_devices string")
        except Exception as e:
            print(f"Failed to set memory_devices : {e}")

    def get_memory_stat(self, real_time=True, cache_data=None):
        property_name = "memory_stat"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "cpuinfo"
            }
            print("📤 MEMORY STAT COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 MEMORY STAT RESPONSE:", output)

            return output
        else:
            print("📦 MEMORY STAT RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    def set_memory_stat(self, memory_stat):
        try:
            if isinstance(memory_stat, str):
                memory_stat = json.loads(memory_stat)

            memory_data = memory_stat.get("memory", {})
            percent_consumed = memory_data.get("percentConsumed")

            # Validate percentConsumed is a number and within a reasonable range 0-100
            if percent_consumed is None or not isinstance(percent_consumed, (int, float)) or not (0 <= percent_consumed <= 100):
                print("Invalid or missing 'percentConsumed' value.")
                return

            insert_query = text("""
                INSERT INTO memory_stat (device_id, memory_usage, last_updated_on)
                VALUES (:device_id, :memory_usage, :last_updated_on)
            """)

            data = {
                "device_id": self.device_id,
                "memory_usage": percent_consumed,
                "last_updated_on": datetime.utcnow()
            }

            self.connection.execute(insert_query, data)
            self.connection.commit()

            print(f"Inserted memory stat for device_id {self.device_id} with memory usage {percent_consumed}%.")

        except json.JSONDecodeError:
            print("Invalid JSON format in memory_stat string")
        except Exception as e:
            print(f"Failed to set memory stat: {e}")

    def get_pci_devices(self, real_time=True, cache_data=None):
        property_name = "pci_devices"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 PCI DEVICES COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 PCI DEVICES RESPONSE:", output)

            return output
        else:
            print("📦 PCI DEVICES RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    def set_pci_devices(self, data):
        try:
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    print("⚠️ Invalid JSON format in wmi_bios")
                    return
            print("DATA : ", repr(data))
            pci_devices = []
            if "hardware" in data and "linux" in data['hardware'] and "pci" in data["hardware"]["linux"]:
                pci_devices = data["hardware"]["linux"]["pci"]
            elif "windows" in data and "pci" in data["windows"]:
                pci_devices = data["windows"]["pci"]

            print("PCI DEVICES DATA : ", repr(pci_devices))
            
            required_fields = {"bus", "device", "manufacturer", "description"}
            valid_pci_devices = [d for d in pci_devices if required_fields.issubset(d.keys())]
            
            if valid_pci_devices:
                # Delete existing entries for this device_id
                delete_query = text("""
                    DELETE FROM pci_devices WHERE device_id = :device_id
                """)
                self.connection.execute(delete_query, {"device_id": self.device_id})
                self.connection.commit()
            
            insert_query = text("""
                INSERT INTO pci_devices (
                    device_id, pci_slot, pci_class, vendor, vendor_id, model, model_id,
                    pci_class_id, pci_subclass_id, pci_subclass,
                    subsystem_vendor_id, subsystem_vendor,
                    subsystem_model_id, subsystem_model, created_at
                ) VALUES (
                    :device_id, :pci_slot, :pci_class, :vendor, :vendor_id, :model, :model_id,
                    :pci_class_id, :pci_subclass_id, :pci_subclass,
                    :subsystem_vendor_id, :subsystem_vendor,
                    :subsystem_model_id, :subsystem_model, :created_at
                )
            """)
            
            for pci in valid_pci_devices:
                subsystem = pci.get("subsystem", {})
                data_to_insert = {
                    "device_id": self.device_id,
                    "pci_slot": pci["bus"],              # e.g. "00:00.0"
                    "pci_class": pci["description"],    # e.g. "440FX - 82441FX PMC [Natoma]"
                    "vendor": pci["manufacturer"],      # e.g. "Intel Corporation"
                    "vendor_id": None,                   # unknown from data
                    "model": pci["description"],        # same as pci_class, no distinct model field
                    "model_id": None,                   # unknown from data
                    "pci_class_id": None,
                    "pci_subclass_id": None,
                    "pci_subclass": None,
                    "subsystem_vendor_id": None,
                    "subsystem_vendor": subsystem.get("manufacturer"),
                    "subsystem_model_id": None,
                    "subsystem_model": subsystem.get("description"),
                    "created_at": datetime.utcnow()
                }
                self.connection.execute(insert_query, data_to_insert)
            self.connection.commit()
        except Exception as e:
            print(f"❌ Error in pci_devices : {e}")

    def get_platform_info(self, real_time=True, cache_data=None):
        property_name = "platform_info"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 PLATFORM INFO COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 PLATFORM INFO RESPONSE:", output)

            return output
        else:
            print("📦 PLATFORM INFO RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    def set_platform_info(self, platform_info):
        try:
            # Convert string to JSON object
            if isinstance(platform_info, str):
                platform_info = json.loads(platform_info)

            identifier_obj = platform_info.get("hardware", {}).get("identifiers", {})

            # Required fields
            required_fields = {"bios_vendor", "bios_version", "bios_date", "bios_mode"}
            if not required_fields.issubset(identifier_obj):
                missing = required_fields - identifier_obj.keys()
                print(f"Missing required fields in identifiers: {missing}")
                return

            # Extract values
            vendor = identifier_obj["bios_vendor"]
            version = identifier_obj["bios_version"]
            date = identifier_obj["bios_date"]
            firmware_type = identifier_obj["bios_mode"]

            # Delete existing entry
            delete_query = text("DELETE FROM platform_info WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert new entry
            insert_query = text("""
                INSERT INTO platform_info (device_id, vendor, version, date, firmware_type)
                VALUES (:device_id, :vendor, :version, :date, :firmware_type)
            """)
            self.connection.execute(insert_query, {
                "device_id": self.device_id,
                "vendor": vendor,
                "version": version,
                "date": date,
                "firmware_type": firmware_type.lower()
            })

            # Commit changes
            self.connection.commit()
            print("Platform info successfully set.")

        except json.JSONDecodeError:
            print("Invalid JSON format in platform_info string.")
        except Exception as e:
            self.connection.rollback()
            print(f"Failed to set platform info: {e}")

    # def get_system_info(self):
    #     # First command: "sysinfo"
    #     sysinfo_command = {
    #         "action": "msg",
    #         "nodeid": self.node_id,
    #         "type": "console",
    #         "value": "sysinfo"
    #     }
    #     print("PROCESS COMMAND", sysinfo_command)
    #     self.client.send_command(sysinfo_command)
    #     sysinfo_output = self.client.receive_messages()
    #     print("PROCESS RESPONSE SYSINFO", sysinfo_output)

    #     # Second command: "smbios"
    #     smbios_command = {
    #         "action": "msg",
    #         "nodeid": self.node_id,
    #         "type": "console",
    #         "value": "smbios"
    #     }
    #     print("PROCESS COMMAND", smbios_command)
    #     self.client.send_command(smbios_command)
    #     smbios_output = self.client.receive_messages()
    #     print("PROCESS RESPONSE SMBIOS", smbios_output)

    #     return {"sysinfo": sysinfo_output, "smbios": smbios_output}

    def get_system_info(self, real_time=True, cache_data=None):
        property_name = "system_info"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            # First command: "sysinfo"
            sysinfo_command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 SYSTEM INFO SYSINFO COMMAND:", sysinfo_command)
            self.client.send_command(sysinfo_command)
            sysinfo_output = self.client.receive_messages()
            print("📥 SYSTEM INFO SYSINFO RESPONSE:", sysinfo_output)

            # Second command: "smbios"
            smbios_command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "smbios"
            }
            print("📤 SYSTEM INFO SMBIOS COMMAND:", smbios_command)
            self.client.send_command(smbios_command)
            smbios_output = self.client.receive_messages()
            print("📥 SYSTEM INFO SMBIOS RESPONSE:", smbios_output)

            return {"sysinfo": sysinfo_output, "smbios": smbios_output}
        else:
            print("📦 SYSTEM INFO RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
        
    def fix_smbios_string(self,s):
        # Normalize line endings
        s = s.replace('\r\n', '\n').replace('\r', '\n')
        
        # Quote top-level keys
        s = re.sub(r'^(\s*)([A-Za-z0-9 _-]+):', r'\1"\2":', s, flags=re.MULTILINE)
        
        # Quote numeric keys (e.g., 0:)
        s = re.sub(r'(\n\s*)(\d+):', r'\1"\2":', s)

        # Add commas between string values and next keys
        s = re.sub(r'("\s*:\s*[^,\{\[\n]+)(\n\s*")', r'\1,\2', s)

        # Add commas between adjacent key-value pairs in same object
        s = re.sub(r'(".*?")(\s*:)(".*?")(\s*")', r'\1\2\3,\4', s)

        # Add commas between closing brace and next numeric key
        s = re.sub(r'(\})\s*(\d+":)', r'\1,\n\2', s)

        # Add commas between closing brace and next string key
        s = re.sub(r'(\})\s*("[A-Za-z0-9 _-]+":)', r'\1,\n\2', s)

        # Ensure proper value termination before closing braces/brackets
        s = re.sub(r'"\s*\n\s*([}\]])', r'",\n\1', s)

        # Remove trailing commas before closing braces/brackets
        s = re.sub(r',\s*([\]}])', r'\1', s)

        return s

    def parse_smbios_json(self,broken_json_string):
        fixed_str = self.fix_smbios_string(broken_json_string)
        try:
            return json.loads(fixed_str)
        except Exception as e:
            print("❌ Failed to parse JSON:", e)
            return None
    
    # def set_system_info(self, data: dict):
    #     try:
    #         # Parse sysinfo
    #         if isinstance(data.get("sysinfo"), str):
    #             sysinfo_data = json.loads(data["sysinfo"])
    #         else:
    #             sysinfo_data = data.get("sysinfo", {})

    #         # Parse smbios
    #         if isinstance(data.get("smbios"), str):
    #             smbios_data = self.parse_smbios_json(data["smbios"])
    #             # smbios_data = json.loads(data["smbios"])
    #             print("SMBIOS DATA : ", smbios_data)
    #         else:
    #             smbios_data = data.get("smbios", {})

    #         try:
    #             osinfo = sysinfo_data.get("hardware", {}).get("windows", {}).get("osinfo", {})
    #             cpu = sysinfo_data.get("hardware", {}).get("windows", {}).get("cpu", [{}])[0]
    #             memory = sysinfo_data.get("hardware", {}).get("windows", {}).get("memory", [{}])[0]
    #             identifiers = sysinfo_data.get("hardware", {}).get("identifiers", {})

    #             smbios_cpu = smbios_data.get('processorInfo', {}).get('0', {})
    #             smbios_sys = smbios_data.get("systemInfo", {})

    #             print("SMBIOS cpu : ", repr(smbios_cpu))
    #             print("SMBIOS sys : ", repr(smbios_sys))

    #             hostname = osinfo.get("CSName")
    #             uuid = smbios_sys.get("uuid")

    #             if not hostname or not uuid:
    #                 print(f"[SystemInfo] Skipped update for device {self.device_id}: Missing hostname or UUID")
    #                 return

    #             # DELETE old record
    #             delete_query = text("DELETE FROM system_info WHERE device_id = :device_id")
    #             self.connection.execute(delete_query, {"device_id": self.device_id})
    #             self.connection.commit()
    #             # INSERT new record
    #             insert_query = text("""
    #                 INSERT INTO system_info (
    #                     device_id, hostname, uuid, cpu_type, cpu_subtype, cpu_brand,
    #                     cpu_physical_cores, cpu_logical_cores, physical_memory, hardware_vendor,
    #                     hardware_model, hardware_version, board_vendor, board_model,
    #                     board_version, computer_name
    #                 ) VALUES (
    #                     :device_id, :hostname, :uuid, :cpu_type, :cpu_subtype, :cpu_brand,
    #                     :cpu_physical_cores, :cpu_logical_cores, :physical_memory, :hardware_vendor,
    #                     :hardware_model, :hardware_version, :board_vendor, :board_model,
    #                     :board_version, :computer_name
    #                 )
    #             """)
    #             self.connection.execute(insert_query, {
    #                 "device_id": self.device_id,
    #                 "hostname": hostname,
    #                 "uuid": uuid,
    #                 "cpu_type": cpu.get("Caption"),
    #                 "cpu_subtype": smbios_cpu.get("Processor"),
    #                 "cpu_brand": cpu.get("Name"),
    #                 "cpu_physical_cores": smbios_cpu.get("Cores"),
    #                 "cpu_logical_cores": smbios_cpu.get("Threads"),
    #                 "physical_memory": memory.get("Capacity"),
    #                 "hardware_vendor": memory.get("Manufacturer"),
    #                 "hardware_model": identifiers.get("product_name"),
    #                 "hardware_version": smbios_cpu.get("Version"),
    #                 "board_vendor": memory.get("Manufacturer"),
    #                 "board_model": identifiers.get("product_name"),
    #                 "board_version": smbios_cpu.get("Version"),
    #                 "computer_name": hostname,
    #             })
    #             self.connection.commit()
    #         except:
    #             identifiers = sysinfo_data.get("hardware", {}).get("identifiers", {})
    #             linux_data = sysinfo_data.get("hardware", {}).get("linux", {})
    #             # DELETE old record
    #             delete_query = text("DELETE FROM system_info WHERE device_id = :device_id")
    #             self.connection.execute(delete_query, {"device_id": self.device_id})
    #             self.connection.commit()
    #             # INSERT new record
    #             insert_query = text("""
    #                 INSERT INTO system_info (
    #                     device_id, hostname, uuid, cpu_type, cpu_subtype, cpu_brand,
    #                     cpu_physical_cores, cpu_logical_cores, physical_memory, hardware_vendor,
    #                     hardware_model, hardware_version, board_vendor, board_model,
    #                     board_version, computer_name
    #                 ) VALUES (
    #                     :device_id, :hostname, :uuid, :cpu_type, :cpu_subtype, :cpu_brand,
    #                     :cpu_physical_cores, :cpu_logical_cores, :physical_memory, :hardware_vendor,
    #                     :hardware_model, :hardware_version, :board_vendor, :board_model,
    #                     :board_version, :computer_name
    #                 )
    #             """)
    #             self.connection.execute(insert_query, {
    #                 "device_id": self.device_id,
    #                 "hostname": None,
    #                 "uuid": identifiers.get("product_uuid"),
    #                 "cpu_type": identifiers.get("cpu_name"),
    #                 "cpu_subtype": None,
    #                 "cpu_brand": linux_data.get("chassis_vendor"),
    #                 "cpu_physical_cores": None,
    #                 "cpu_logical_cores": None,
    #                 "physical_memory": None,
    #                 "hardware_vendor": linux_data.get("chassis_vendor"),
    #                 "hardware_model": linux_data.get("chassis_vendor"),
    #                 "hardware_version": linux_data.get("chassis_version"),
    #                 "board_vendor": linux_data.get("chassis_vendor"),
    #                 "board_model": linux_data.get("chassis_vendor"),
    #                 "board_version": linux_data.get("chassis_version"),
    #                 "computer_name": None,
    #             })
    #             self.connection.commit()

    #     except json.JSONDecodeError:
    #         print("Invalid JSON format in system_info string")
    #     except Exception as e:
    #         print(f"[SystemInfo] Error for device {self.device_id}: {e}")


    def set_system_info(self, data: dict):
        try:
            # Parse sysinfo and smbios
            sysinfo_data = json.loads(data.get("sysinfo", "{}")) if isinstance(data.get("sysinfo"), str) else data.get("sysinfo", {})
            smbios_data = self.parse_smbios_json(data["smbios"]) if isinstance(data.get("smbios"), str) else data.get("smbios", {})

            def delete_old_record():
                delete_query = text("DELETE FROM system_info WHERE device_id = :device_id")
                self.connection.execute(delete_query, {"device_id": self.device_id})
                self.connection.commit()

            def insert_record(payload):
                insert_query = text("""
                    INSERT INTO system_info (
                        device_id, hostname, uuid, cpu_type, cpu_subtype, cpu_brand,
                        cpu_physical_cores, cpu_logical_cores, physical_memory, hardware_vendor,
                        hardware_model, hardware_version, board_vendor, board_model,
                        board_version, computer_name
                    ) VALUES (
                        :device_id, :hostname, :uuid, :cpu_type, :cpu_subtype, :cpu_brand,
                        :cpu_physical_cores, :cpu_logical_cores, :physical_memory, :hardware_vendor,
                        :hardware_model, :hardware_version, :board_vendor, :board_model,
                        :board_version, :computer_name
                    )
                """)
                self.connection.execute(insert_query, payload)
                self.connection.commit()

            try:
                # Attempt Windows parsing
                osinfo = sysinfo_data.get("hardware", {}).get("windows", {}).get("osinfo", {})
                cpu = sysinfo_data.get("hardware", {}).get("windows", {}).get("cpu", [{}])[0]
                memory = sysinfo_data.get("hardware", {}).get("windows", {}).get("memory", [{}])[0]
                identifiers = sysinfo_data.get("hardware", {}).get("identifiers", {})

                smbios_cpu = smbios_data.get('processorInfo', {}).get('0', {})
                smbios_sys = smbios_data.get("systemInfo", {})

                hostname = osinfo.get("CSName")
                uuid = smbios_sys.get("uuid")

                if not hostname or not uuid:
                    print(f"[SystemInfo] Skipped update for device {self.device_id}: Missing hostname or UUID")
                    return

                delete_old_record()
                insert_record({
                    "device_id": self.device_id,
                    "hostname": hostname,
                    "uuid": uuid,
                    "cpu_type": cpu.get("Caption"),
                    "cpu_subtype": smbios_cpu.get("Processor"),
                    "cpu_brand": cpu.get("Name"),
                    "cpu_physical_cores": smbios_cpu.get("Cores"),
                    "cpu_logical_cores": smbios_cpu.get("Threads"),
                    "physical_memory": memory.get("Capacity"),
                    "hardware_vendor": memory.get("Manufacturer"),
                    "hardware_model": identifiers.get("product_name"),
                    "hardware_version": smbios_cpu.get("Version"),
                    "board_vendor": memory.get("Manufacturer"),
                    "board_model": identifiers.get("product_name"),
                    "board_version": smbios_cpu.get("Version"),
                    "computer_name": hostname,
                })

            except Exception as e:
                print(f"[SystemInfo] Windows parsing failed, falling back to Linux. Error: {e}")
                identifiers = sysinfo_data.get("hardware", {}).get("identifiers", {})
                linux_data = sysinfo_data.get("hardware", {}).get("linux", {})

                delete_old_record()
                insert_record({
                    "device_id": self.device_id,
                    "hostname": None,
                    "uuid": identifiers.get("product_uuid"),
                    "cpu_type": identifiers.get("cpu_name"),
                    "cpu_subtype": None,
                    "cpu_brand": linux_data.get("chassis_vendor"),
                    "cpu_physical_cores": None,
                    "cpu_logical_cores": None,
                    "physical_memory": None,
                    "hardware_vendor": linux_data.get("chassis_vendor"),
                    "hardware_model": linux_data.get("chassis_vendor"),
                    "hardware_version": linux_data.get("chassis_version"),
                    "board_vendor": linux_data.get("chassis_vendor"),
                    "board_model": linux_data.get("chassis_vendor"),
                    "board_version": linux_data.get("chassis_version"),
                    "computer_name": None,
                })

        except json.JSONDecodeError:
            print("Invalid JSON format in system_info string")
        except Exception as e:
            print(f"[SystemInfo] Error for device {self.device_id}: {e}")

    def get_users(self, real_time=True, cache_data=None):
        property_name = "users"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "nodes",
                "id": "",
                "skip": "0",
                # "value": "sysinfo"
            }
            print("📤 users COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 users RESPONSE:", output)

            return output
        else:
            print("📦 users RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
        
    def extract_nodes_with_users(self,payload):
        result = []
        for node_list in payload.values():
            for node in node_list:
                users = node.get("users", [])
                if users:  # Only include if users list is not empty
                    result.append({node["_id"]: users})
        return result
    
    # def set_users(self, users):
    #     print("📥 Raw user data:\n" + repr(users))  # Debug output

    #     # valid_entries = []
    #     # for line in users.strip().splitlines():
    #     #     try:
    #     #         parsed = json.loads(line)
    #     #         if isinstance(parsed, dict):
    #     #             valid_entries.append(parsed)
    #     #     except json.JSONDecodeError:
    #     #         print(f"⚠️ Skipping non-JSON line: {repr(line)}")
    #     #         continue

    #     # if not valid_entries:
    #     #     print("⚠️ No valid user entries found.")
    #     #     return

    #     if isinstance(users, str):
    #         users = json.loads(users)

    #     users_dict = self.extract_nodes_with_users(users)
    #     print("USERS DICT : ", users_dict)

    #     for k, v in users_dict:

    #     # Delete existing records
    #     delete_query = text("DELETE FROM user_info WHERE device_id = :device_id")
    #     self.connection.execute(delete_query, {"device_id": self.device_id})

    #     # Insert new records
    #     insert_query = text("""
    #         INSERT INTO user_info (device_id, username, is_connected)
    #         VALUES (:device_id, :username, :is_connected)
    #     """)

    #     # reps = []
    #     # for entry in valid_entries:
    #     #     state = entry.get("State", "").lower()
    #     #     is_connected = state in ("connected", "listening")

    #     #     reps.append({
    #     #         "device_id": self.device_id,
    #     #         "username": str(entry.get("SessionId")),
    #     #         "is_connected": is_connected
    #     #     })

    #     self.connection.execute(insert_query, reps)
    #     self.connection.commit()
    #     print(f"✅ Inserted {len(reps)} user(s) for device {self.device_id}")

    def set_users(self, users):

        print("📥 Raw user data:\n" + repr(users))  # Debug output

        if isinstance(users, str):
            users = json.loads(users)

        users_dicts = self.extract_nodes_with_users(users)  # List of dicts

        for node_entry in users_dicts:
            for node_id, usernames in node_entry.items():
                # Get device_id (machine_id) from hosts table
                query = text("SELECT machine_id FROM hosts WHERE nem_agent_id = :node_id")
                result = self.connection.execute(query, {"node_id": node_id}).fetchone()

                if not result:
                    print(f"❌ No device found for node_id: {node_id}")
                    continue

                device_id = result[0]

                # Delete existing records for this device_id
                delete_query = text("DELETE FROM user_info WHERE device_id = :device_id")
                self.connection.execute(delete_query, {"device_id": device_id})

                # Prepare insert values
                reps = []
                for username in usernames:
                    reps.append({
                        "device_id": device_id,
                        "username": username,
                        "is_connected": True
                    })

                # Insert new user records
                insert_query = text("""
                    INSERT INTO user_info (device_id, username, is_connected)
                    VALUES (:device_id, :username, :is_connected)
                """)
                self.connection.execute(insert_query, reps)
                self.connection.commit()

                print(f"✅ Inserted {len(reps)} user(s) for device {device_id}")

    def get_wmi_bios(self, real_time=True, cache_data=None):
        property_name = "wmi_bios"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 WMI_BIOS COMMAND:", command)
            self.client.send_command(command)

            output = self.client.receive_messages()
            print("📥 WMI_BIOS RESPONSE:", output)
            return output
        else:
            print("📦 WMI_BIOS RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    def set_wmi_bios(self, wmi_bios):
        try:
            if isinstance(wmi_bios, str):
                try:
                    wmi_bios = json.loads(wmi_bios)
                except json.JSONDecodeError:
                    print("⚠️ Invalid JSON format in wmi_bios")
                    return

            identifiers = wmi_bios.get("hardware", {}).get("identifiers", {})
            if not isinstance(identifiers, dict) or not identifiers:
                print("⚠️ No valid identifier data found")
                return

            insert_data = []

            for key, value in identifiers.items():
                if isinstance(value, (str, int, float)) and value not in ["", None]:
                    insert_data.append((key, str(value)))

                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, (str, int, float)):
                            insert_data.append((f"{key}_{i}", str(item)))

                        elif isinstance(item, dict):
                            for sub_key, sub_value in item.items():
                                if sub_value not in ["", None]:
                                    insert_data.append((f"{key}_{i}_{sub_key}", str(sub_value)))

            if not insert_data:
                print("⚠️ No valid key-value pairs to insert")
                return

            # Delete existing entries for this device
            delete_query = text("DELETE FROM wmi_bios_info WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert new entries
            insert_query = text("""
            INSERT INTO wmi_bios_info (device_id, name, value)
            VALUES (:device_id, :name, :value)
            """)

            for name, value in insert_data:
                self.connection.execute(insert_query, {
                    "device_id": self.device_id,
                    "name": name,
                    "value": value
                })

            self.connection.commit()
            print(f"✅ Inserted {len(insert_data)} BIOS info entries for device_id {self.device_id}")

        except Exception as e:
            print(f"❌ Error in set_wmi_bios: {e}")

    def get_nt_domain(self, real_time=True, cache_data=None):
        property_name = "nt_domain"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "domain"
            }
            print("📤 NT_DOMAIN COMMAND:", command)
            self.client.send_command(command)

            output = self.client.receive_messages()
            print("📥 NT_DOMAIN RESPONSE:", output)
            return output
        else:
            print("📦 NT_DOMAIN RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    def set_nt_domain(self, nt_domain):
        try:
            # Normalize and prepare raw input string
            entries = []
            if isinstance(nt_domain, str):
                nt_domain = nt_domain.strip()
                lines = nt_domain.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and obj.get("Name"):
                            entries.append(obj)
                    except json.JSONDecodeError:
                        print(f"⚠️ Skipping invalid JSON entry: {line}")
            elif isinstance(nt_domain, dict) and nt_domain.get("Name") and nt_domain.get("Domain"):
                entries = [nt_domain]
            else:
                print("⚠️ nt_domain is not in valid format")
                return

            if not entries:
                print("⚠️ No valid domain entries found")
                return

            # Delete existing entries for this device_id
            delete_query = text("DELETE FROM ntdomains WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert all valid domain records
            insert_query = text("""
                INSERT INTO ntdomains (device_id, name, domain_name)
                VALUES (:device_id, :name, :domain_name)
            """)
            for entry in entries:
                self.connection.execute(insert_query, {
                    "device_id": self.device_id,
                    "name": entry["Name"],
                    "domain_name": entry["Domain"] if entry["Domain"] else None
                })

            self.connection.commit()
            print(f"✅ Saved {len(entries)} NT domain entries for device_id {self.device_id}")

            # ⏬ Check if final_host_name is empty for this device_id
            check_query = text("""
                SELECT final_host_name FROM hosts_view WHERE machine_id = :device_id
            """)
            result = self.connection.execute(check_query, {"device_id": self.device_id}).fetchone()

            if result and (result[0] is None or result[0].strip() == ""):
                update_query = text("""
                    UPDATE hosts SET host_name = :host_name WHERE machine_id = :device_id
                """)
                self.connection.execute(update_query, {
                    "host_name": entries[0]["Name"],
                    "device_id": self.device_id
                })
                self.connection.commit()
                print(f"🛠️ Updated host_name for device_id {self.device_id}")

        except Exception as e:
            print(f"❌ Error in set_nt_domain: {e}")


    def get_os_version(self, real_time=True, cache_data=None):
        property_name = "os_version"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 OS_VERSION COMMAND:", command)
            self.client.send_command(command)

            output = self.client.receive_messages()
            print("📥 OS_VERSION RESPONSE:", output)
            return output
        else:
            print("📦 OS_VERSION RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    # def set_os_version(self, os_version):
    #     try:
    #         if isinstance(os_version, str):
    #             try:
    #                 os_version = json.loads(os_version)
    #             except json.JSONDecodeError:
    #                 print("⚠️ Invalid JSON format in os_version")
    #                 return

    #         osinfo = os_version.get("hardware", {}).get("windows", {}).get("osinfo", {})
    #         if not isinstance(osinfo, dict) or not osinfo:
    #             print("⚠️ No valid osinfo data found")
    #             return

    #         required_fields = [
    #             "Caption",
    #             "Version",
    #             "BuildNumber",
    #             "CreationClassName",
    #             "CSCreationClassName",
    #             "CSName",
    #             "OSArchitecture"
    #         ]

    #         if not all(osinfo.get(field) for field in required_fields):
    #             print("⚠️ Missing required fields in osinfo")
    #             return

    #         name = osinfo["Caption"]
    #         version = osinfo["Version"]
    #         build = osinfo["BuildNumber"]
    #         platform = osinfo["CreationClassName"]
    #         platform_like = osinfo["CSCreationClassName"]
    #         codename = osinfo["CSName"]
    #         arch = osinfo["OSArchitecture"]

    #         # Delete existing entries
    #         delete_query = text("DELETE FROM os_version WHERE device_id = :device_id")
    #         self.connection.execute(delete_query, {"device_id": self.device_id})

    #         # Insert new entry
    #         insert_query = text("""
    #             INSERT INTO os_version (name, version, build, platform, platform_like, codename, arch, device_id)
    #             VALUES (:name, :version, :build, :platform, :platform_like, :codename, :arch, :device_id)
    #         """)
    #         self.connection.execute(insert_query, {
    #             "name": name,
    #             "version": version,
    #             "build": build,
    #             "platform": platform,
    #             "platform_like": platform_like,
    #             "codename": codename,
    #             "arch": arch,
    #             "device_id": self.device_id
    #         })

    #         self.connection.commit()

    #     except Exception as e:
    #         print(f"❌ Error in set_os_version: {e}")


    def set_os_version(self, os_version):
        try:
            if isinstance(os_version, str):
                try:
                    os_version = json.loads(os_version)
                except json.JSONDecodeError:
                    print("⚠️ Invalid JSON format in os_version")
                    return

            # ✅ WINDOWS PATH (existing logic)
            osinfo = os_version.get("hardware", {}).get("windows", {}).get("osinfo", {})
            if isinstance(osinfo, dict) and osinfo:
                required_fields = [
                    "Caption",
                    "Version",
                    "BuildNumber",
                    "CreationClassName",
                    "CSCreationClassName",
                    "CSName",
                    "OSArchitecture"
                ]

                if not all(osinfo.get(field) for field in required_fields):
                    print("⚠️ Missing required fields in osinfo")
                    return

                name = osinfo["Caption"]
                version = osinfo["Version"]
                build = osinfo["BuildNumber"]
                platform = osinfo["CreationClassName"]
                platform_like = osinfo["CSCreationClassName"]
                codename = osinfo["CSName"]
                arch = osinfo["OSArchitecture"]

            else:
                # ✅ LINUX PATH (new logic)
                usb_devices = os_version.get("hardware", {}).get("linux", {}).get("usb", [])
                if not usb_devices or not isinstance(usb_devices, list):
                    print("⚠️ No USB devices found for Linux OS info")
                    return

                manufacturer = usb_devices[0].get("Manufacturer", "")
                if "linux" not in manufacturer.lower():
                    print(f"⚠️ USB manufacturer '{manufacturer}' does not contain 'linux'")
                    return

                # Set dummy or inferred values for Linux
                name = manufacturer
                version = None
                build = None
                platform = "LinuxPlatform"
                platform_like = "Linux"
                codename = None
                arch = None

            # Delete existing entries
            delete_query = text("DELETE FROM os_version WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert new entry
            insert_query = text("""
                INSERT INTO os_version (name, version, build, platform, platform_like, codename, arch, device_id)
                VALUES (:name, :version, :build, :platform, :platform_like, :codename, :arch, :device_id)
            """)
            self.connection.execute(insert_query, {
                "name": name,
                "version": version,
                "build": build,
                "platform": platform,
                "platform_like": platform_like,
                "codename": codename,
                "arch": arch,
                "device_id": self.device_id
            })

            self.connection.commit()

        except Exception as e:
            print(f"❌ Error in set_os_version: {e}")

    def get_interface_addresses(self, real_time=True, cache_data=None):
        property_name = "interface_addresses"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        print("🧠 FULL MEMORY CACHE:", cache_data)

        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "netinfo"
            }
            print("📤 INTERFACE_ADDRESSES COMMAND:", command)
            self.client.send_command(command)

            output = self.client.receive_messages()
            print("📥 INTERFACE_ADDRESSES RESPONSE:", output)
            return output
        else:
            print("📦 INTERFACE_ADDRESSES RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
    
    # def set_interface_addresses(self, netinfo):
    #     try:
    #         if isinstance(netinfo, str):
    #             # Decode escaped sequences like \r\n, \t, etc. to real characters
    #             netinfo = netinfo.encode('utf-8').decode('unicode_escape')

    #             # Normalize line endings
    #             netinfo = netinfo.replace('\r\n', '\n')

    #             # Quote keys before colons
    #             netinfo = re.sub(
    #                 r'(^|\{|,|\n)\s*([^\s":][^":]*?)\s*:',  # match keys not already quoted
    #                 lambda m: f'{m.group(1)}"{m.group(2).strip()}":',
    #                 netinfo
    #             )

    #             # Insert commas after closing braces if followed by another quoted key
    #             netinfo = re.sub(r'(\})(\s*\n\s*")', r'\1,\2', netinfo)

    #             # Remove trailing commas before closing braces (optional)
    #             netinfo = re.sub(r',(\s*[\}\]])', r'\1', netinfo)

    #             # Now parse the JSON
    #             netinfo_json = json.loads(netinfo)
    #         else:
    #             netinfo_json = netinfo

    #         print("✅ Parsed netinfo JSON:")
    #         print(json.dumps(netinfo_json, indent=2))

    #         valid_entries = []

    #         for interface, configs in netinfo_json.items():
    #             # Trim interface name to the first word (e.g., "Ethernet 2" → "Ethernet")
    #             short_interface = interface.split()[0]

    #             for config in configs.values():
    #                 if not isinstance(config, dict):
    #                     continue

    #                 mac = config.get("mac")
    #                 status = config.get("status")
    #                 iface_type = config.get("type")

    #                 if not all([mac, status, iface_type]):
    #                     continue

    #                 entry = {
    #                     "device_id": self.device_id,
    #                     "interface": short_interface,
    #                     "type": iface_type,
    #                     "mac": mac,
    #                     "connection_status": status
    #                 }
    #                 valid_entries.append(entry)

    #         if not valid_entries:
    #             print("⚠️ No valid netinfo entries found.")
    #             return

    #         # Clear existing entries for this device
    #         delete_query = text("DELETE FROM interface_details WHERE device_id = :device_id")
    #         self.connection.execute(delete_query, {"device_id": self.device_id})

    #         # Insert new entries
    #         for entry in valid_entries:
    #             columns = ', '.join(entry.keys())
    #             placeholders = ', '.join([f":{k}" for k in entry])
    #             insert_query = text(f"INSERT INTO interface_details ({columns}) VALUES ({placeholders})")
    #             self.connection.execute(insert_query, entry)

    #         self.connection.commit()
    #         print(f"✅ Inserted {len(valid_entries)} netinfo entries for device_id {self.device_id}")

    #     except json.JSONDecodeError as e:
    #         print(f"❌ Failed to parse netinfo string: {e}")
    #     except Exception as e:
    #         print(f"❌ Failed to set netinfo: {e}")

    def set_interface_addresses(self, netinfo):
        def fix_netinfo_string(s):
            s = s.replace('\r\n', '\n').replace('\r', '\n')
            s = re.sub(r'^(\s*)([A-Za-z0-9 _-]+):', r'\1"\2":', s, flags=re.MULTILINE)
            s = re.sub(r'(\n\s*)(\d+):', r'\1"\2":', s)
            s = re.sub(r'("\s*:\s*[^,\{\[\n]+)(\n\s*")', r'\1,\2', s)
            s = re.sub(r'(".*?")(\s*:)(".*?")(\s*")', r'\1\2\3,\4', s)
            s = re.sub(r'(\})\s*(\d+":)', r'\1,\n\2', s)
            s = re.sub(r'(\})\s*("[A-Za-z0-9 _-]+":)', r'\1,\n\2', s)
            s = re.sub(r'"\s*\n\s*([}\]])', r'",\n\1', s)
            s = re.sub(r',\s*([\]}])', r'\1', s)
            return s

        try:
            if isinstance(netinfo, str):
                netinfo = netinfo.strip()
                try:
                    netinfo_json = json.loads(netinfo)
                except json.JSONDecodeError:
                    fixed_str = fix_netinfo_string(netinfo)
                    netinfo_json = json.loads(fixed_str)
            elif isinstance(netinfo, dict):
                netinfo_json = netinfo
            else:
                print("⚠️ netinfo must be a string or dict.")
                return

            print("✅ Parsed interface addresses JSON.")

            entries = []
            for interface, configs in netinfo_json.items():
                if not isinstance(configs, dict):
                    continue

                short_interface = interface.split()[0]

                for _, config in configs.items():
                    if not isinstance(config, dict):
                        continue

                    ip_address = config.get("address")
                    netmask = config.get("netmask")
                    iface_type = config.get("type")

                    if not ip_address or not iface_type:
                        continue

                    entry = {
                        "device_id": self.device_id,
                        "interface": short_interface,
                        "friendly_name": short_interface,
                        "address": ip_address,
                        "type": iface_type
                    }

                    if netmask:
                        entry["mask"] = netmask

                    entries.append(entry)

            if not entries:
                print("⚠️ No valid interface entries found.")
                return

            delete_query = text("DELETE FROM interface_addresses WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            for entry in entries:
                keys = ', '.join(entry.keys())
                vals = ', '.join([f':{k}' for k in entry])
                insert = text(f"INSERT INTO interface_addresses ({keys}) VALUES ({vals})")
                self.connection.execute(insert, entry)

            self.connection.commit()
            print(f"✅ Stored {len(entries)} interface addresses for device {self.device_id}")

        except json.JSONDecodeError as e:
            print(f"❌ Failed to parse netinfo string: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

    def get_mounts(self, real_time=True, cache_data=None):
        property_name = "mounts"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {} 

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "msg",
                "nodeid": self.node_id,
                "type": "console",
                "value": "sysinfo"
            }
            print("📤 MOUNTS COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 MOUNTS RESPONSE:", output)

            return output
        else:
            print("📦 MOUNTS RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
        
    def set_mounts(self, cpuinfo):
        try:
            # Convert string to JSON object
            if isinstance(cpuinfo, str):
                cpuinfo = json.loads(cpuinfo)

            valid_entries = []

            # Handle Windows drives
            # windows_drives = cpuinfo.get("hardware", {}).get("windows", {}).get("drives", [])
            # if isinstance(windows_drives, list):
            #     for drive in windows_drives:
            #         if not isinstance(drive, dict):
            #             continue

            #         required_fields = ["Caption", "DeviceID", "Model", "Partitions", "Size"]
            #         if not all(drive.get(field) for field in required_fields):
            #             continue  # Skip incomplete entries

            #         entry = {
            #             "device_id": self.device_id,
            #             "disk_size": drive["Size"],
            #             "partitions": drive["Partitions"],
            #             "hardware_model": drive["Model"],
            #             "description": drive["Caption"]
            #         }
            #         valid_entries.append(entry)

            # Handle Linux volumes
            linux_volumes = cpuinfo.get("hardware", {}).get("linux", {}).get("volumes", [])
            if isinstance(linux_volumes, list):
                for volume in linux_volumes:
                    if not isinstance(volume, dict):
                        continue

                    required_fields = ["mount_point", "type", "size", "used", "available"]
                    if not all(volume.get(field) for field in required_fields):
                        continue  # Skip incomplete entries

                    entry = {
                        "device_id": self.device_id,
                        "path": volume["mount_point"],
                        "type": volume["type"],
                        "blocks_size": volume["size"],
                        "blocks_available": volume["available"]
                    }
                    valid_entries.append(entry)

            if not valid_entries:
                return

            # Clear existing disk info for the device
            delete_query = text("DELETE FROM mounts WHERE device_id = :device_id")
            self.connection.execute(delete_query, {"device_id": self.device_id})

            # Insert new disk info
            for entry in valid_entries:
                columns = ', '.join(entry.keys())
                placeholders = ', '.join([f":{k}" for k in entry])
                insert_query = text(f"INSERT INTO mounts ({columns}) VALUES ({placeholders})")
                self.connection.execute(insert_query, entry)

            self.connection.commit()

        except json.JSONDecodeError:
            print("Invalid JSON format in diskinfo string")
        except Exception as e:
            print(f"Failed to set DISK info: {e}")

    def get_av_status(self,payload):
        """
        Given a payload with node details, return a list of node IDs
        where antivirus is present and enabled.
        """
        enabled_nodes = []

        for mesh_id, node_list in payload.items():
            for node in node_list:
                node_id = node.get("_id")
                av_entries = node.get("av")

                if av_entries and isinstance(av_entries, list):
                    # Check if the first AV entry has 'enabled' set to True
                    if av_entries[0].get("enabled") is True:
                        enabled_nodes.append(node_id)

        return enabled_nodes

    def get_antivirus(self, real_time=True, cache_data=None):
        property_name = "cpuinfo"

        if cache_data is None:
            cache_data = {}

        if self.device_id not in cache_data:
            cache_data[self.device_id] = {}

        # Print the full memory cache
        print("🧠 FULL MEMORY CACHE:", cache_data)

        # If real-time is True or no cached data exists
        if real_time or property_name not in cache_data[self.device_id]:
            command = {
                "action": "nodes",
                "id": "",
                "skip": "0",
                # "value": "sysinfo"
            }
            print("📤 anti-virus COMMAND:", command)

            self.client.send_command(command)
            output = self.client.receive_messages()
            print("📥 anti-virus RESPONSE:", output)

            return output
        else:
            print("📦 anti-virus RESPONSE (from memory):")
            return cache_data[self.device_id][property_name]
        
    def set_antivirus(self, nodes):
        try:
            # Convert string to JSON object if needed
            if isinstance(nodes, str):
                nodes = json.loads(nodes)
            print(f"NODES DATA IN SET : {repr(nodes)}")
            result = self.get_av_status(nodes)
            print("FINAL AV DATA :", result)
            for node_id in result:

                av_insert_query = text(f"""
                UPDATE hosts SET antivirus_status = :antivirus_status WHERE nem_agent_id = :node_id;
                """)
                self.connection.execute(av_insert_query, {'node_id': node_id, "antivirus_status" : True})
                self.connection.commit()
                print("ANTI VIRUS STATUS CHANGED FOR NODE ID :", str(node_id))

        except json.JSONDecodeError:
            print("Invalid JSON format in cpuinfo string")
        except Exception as e:
            print(f"Failed to set CPU info: {e}")