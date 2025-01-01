import os
from datetime import datetime

def logo():
    logo = "**************************************************************************************************\n"
    logo += "****************************************  NETVISS SCANNER  ***************************************\n"
    logo += "**************************************************************************************************\n"
    return logo


def log_message(log_type, component, message):
    
    log_type = log_type.upper()
    if log_type not in ("ERROR", "INFO"):
        raise ValueError("log_type must be 'ERROR' or 'INFO'.")

    file_name = f"{datetime.now().strftime('%Y-%m-%d')}-logs.txt"
    log_directory = f"{os.getenv('NETVISS_STORAGE')}/logs/services/{component}/"
    os.makedirs(log_directory, exist_ok=True)  # Ensure the log directory exists
    file_path = os.path.join(log_directory, file_name)

    debug_mode = os.getenv('DEBUG', 'True').lower() == 'true'

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] {log_type}: {message}\n"

    if log_type == "ERROR":
        # Always log and print for ERROR
        with open(file_path, 'a') as log_file:
            log_file.write(log_message)
        print(log_message, end="")
    elif log_type == "INFO" and debug_mode:
        # Log and print only if debug_mode is True for INFO
        with open(file_path, 'a') as log_file:
            log_file.write(log_message)
        print(log_message, end="")