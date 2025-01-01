from sqlalchemy import create_engine
import time

# Database credentials
USERNAME = "postgres"
PASSWORD = "123456"
HOST = "localhost"
PORT = "5432"
DATABASE_NAME = "netviss"

# Database engine
DATABASE_URL = f"postgresql://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE_NAME}?sslmode=disable"
ENGINE = create_engine(
    DATABASE_URL,
    pool_size=500,       
    max_overflow=50,      
    pool_timeout=300,    
    pool_recycle=1800
    )

# Database connection
# def connect():
#     try:
#         conn = ENGINE.connect()
#         log_message("Database connection is established.")
#         return conn
#     except Exception as e:
#         log_message("Database connection failed.")
#         log_message("Error:", e)
#         log_message("Trying to reconnect...")
#         return connect()

def connect(retries=5, delay=5):
    attempt = 0
    while attempt < retries:
        try:
            conn = ENGINE.connect()
            print("Database connection is established.")
            return conn
        except Exception as e:
            attempt += 1
            print(f"Database connection failed on attempt {attempt}/{retries}. Error: {e}")
            if attempt < retries:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print("Max retries reached. Could not establish a connection.")
                raise
    return None

# Database disconnect
# def disconnect(connection):
#     connection.close()
#     log_message("Database connection is disconnected.")

def disconnect(connection):
    try:
        connection.close()
        print("Database connection is disconnected.")
    except Exception as e:
        print(f"Error disconnecting: {e}")

# Database engine close
def close():
    ENGINE.dispose()
    print("Database engine is disposed.")
