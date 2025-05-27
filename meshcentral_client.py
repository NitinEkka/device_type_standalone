import json
import ssl
import time
import requests
from websocket import create_connection, WebSocket
import os
from datetime import datetime, timedelta
import socket
import websocket
import redis

requests.packages.urllib3.disable_warnings()

# LOGIN_URL = "https://192.168.15.15:8086/"
# WS_URL = "wss://192.168.15.15:8086/control.ashx"
# ORIGIN = "https://192.168.30.22"
# NODE_ID = "node//eSP6Du3A87X@Rb1CR4MW9xRUU31DoP6XH2CR7BGMioC3kJzcm0t2VdJ3e6YyS3nP"
FILE_PATH = "mesh.json"


class MeshCentralClient:
    def __init__(self, login_url, ws_url, origin, node_id, username, password):
        self.login_url = login_url
        self.ws_url = ws_url
        self.origin = origin
        self.node_id = node_id
        self.ws: WebSocket = None
        self.username = username
        self.password = password

    # xid=eyJ1c2VyaWQiOiJ1c2VyLy9uZXR2aXNzIiwiaXAiOiIxOTIuMTY4LjMwLjIyIiwieCI6Ikp5VGNjbTQzIn0=; xid.sig=T7l2Csow7kFVa9tFoY6YmI0nejFR07eGXcFUCqTp1sTA_KuTz_V357Tn1ojf1L8_

    # def login_and_connect(self):
    #     redis_client = redis.Redis(host='localhost', port=6379, db=0)  # Adjust connection details as needed

    #     # Try to fetch cookie from Redis
    #     # redis_cookie = redis_client.get('mesh-netviss-cookie')
    #     # if redis_cookie:
    #     #     cookie_header = redis_cookie.decode('utf-8')
    #     #     try:
    #     #         self.ws = create_connection(
    #     #             self.ws_url,
    #     #             header=[
    #     #                 f"Origin: {self.origin}",
    #     #                 f"Cookie: {cookie_header}"
    #     #             ],
    #     #             sslopt={"cert_reqs": ssl.CERT_NONE}
    #     #         )
    #     #         print("✅ Connected to WebSocket with Redis cookie.")
    #     #         return
    #     #     except Exception as e:
    #     #         print(f"❌ Failed to connect with Redis cookie: {e}")
    #     #         # Proceed to login if connection fails

    #     # If no cookie in Redis or connection failed, do login
    #     response = requests.post(
    #         self.login_url,
    #         data="action=login&username=netviss&password=netviss&urlargs=",
    #         headers={"Content-Type": "application/x-www-form-urlencoded"},
    #         verify=False
    #     )

    #     if response.status_code != 200:
    #         raise Exception(f"Login failed: {response.status_code}")

    #     cookies = response.cookies.get_dict()
    #     cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

    #     # Save new cookie in Redis (optional, set expiry if you want)
    #     # redis_client.set('meshcentral_cookie', cookie_header)

    #     self.ws = create_connection(
    #         self.ws_url,
    #         header=[
    #             f"Origin: {self.origin}",
    #             f"Cookie: {cookie_header}"
    #         ],
    #         sslopt={"cert_reqs": ssl.CERT_NONE}
    #     )
    #     print("✅ Connected to WebSocket after login.")

    def login_and_connect(self):

        def is_authenticated(ws, timeout=3):
            start_time = time.time()
            responses = []

            try:
                ws.send('{"action":"ping"}')
                while time.time() - start_time < timeout:
                    try:
                        msg = ws.recv()
                        responses.append(msg)
                        print("📩 WS Response:", msg)

                        # Look for known authentication keys
                        if any(key in msg for key in ['"user"', '"serverinfo"', '"pong"']):
                            return True

                    except websocket.WebSocketTimeoutException:
                        break  # Stop reading if no more messages
            except Exception as e:
                print(f"❌ WebSocket authentication check error: {e}")
                return False

            print("❌ No valid authentication response received.")
            return False

        redis_client = redis.Redis(host='localhost', port=6379, db=0)
        redis_key = 'mesh-netviss-cookie'
        redis_cookie = redis_client.get(redis_key)

        # Try using existing Redis cookie
        if redis_cookie:
            cookie_header = redis_cookie.decode('utf-8')
            print("Cookie : ", cookie_header)
            try:
                self.ws = create_connection(
                    self.ws_url,
                    header=[
                        f"Origin: {self.origin}",
                        f"Cookie: {cookie_header}"
                    ],
                    sslopt={"cert_reqs": ssl.CERT_NONE}
                )
                if is_authenticated(self.ws):
                    print("✅ Connected to WebSocket with Redis cookie.")
                    return
                else:
                    print("⚠️ Redis cookie expired or invalid. Re-authenticating.")
                    self.ws.close()
            except Exception as e:
                print(f"❌ WebSocket connection with Redis cookie failed: {e}")

        # Perform login and fetch fresh cookie
        response = requests.post(
            self.login_url,
            data=f"action=login&username={self.username}&password={self.username}&urlargs=", # data="action=login&username=netviss&password=netviss&urlargs=",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False
        )

        if response.status_code != 200:
            raise Exception(f"Login failed: {response.status_code}")

        cookies = response.cookies.get_dict()
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())

        # Update Redis with new cookie
        redis_client.set(redis_key, cookie_header)

        # Create new connection with updated cookie
        self.ws = create_connection(
            self.ws_url,
            header=[
                f"Origin: {self.origin}",
                f"Cookie: {cookie_header}"
            ],
            sslopt={"cert_reqs": ssl.CERT_NONE}
        )

        if is_authenticated(self.ws):
            print("✅ Connected to WebSocket after login.")
        else:
            raise Exception("❌ Login succeeded, but WebSocket authentication still failed.")

    def send_command(self, command: dict):
        # command = {
        #     "action": "msg",
        #     "nodeid": self.node_id,
        #     "type": "console",
        #     "value": value
        # }
        self.ws.send(json.dumps(command))
        print(f"📤 Sent command: {command}")

    # def receive_messages(self, save_path=FILE_PATH):
    #     try:
    #         while True:
    #             message = self.ws.recv()
    #             print("📩 Received:", message)

    #             try:
    #                 parsed_message = json.loads(message)
    #             except json.JSONDecodeError:
    #                 print("⚠️ Skipping non-JSON message")
    #                 continue

    #             # Save to file
    #             mesh_data = []
    #             if os.path.exists(save_path):
    #                 try:
    #                     with open(save_path, 'r') as f:
    #                         mesh_data = json.load(f)
    #                 except json.JSONDecodeError:
    #                     mesh_data = []

    #             mesh_data.append(parsed_message)

    #             with open(save_path, 'w') as f:
    #                 json.dump(mesh_data, f, indent=2)

    #             # Return if it matches the required condition
    #             if parsed_message.get("action") == "msg" and parsed_message.get("type") == "console":
    #                 try:
    #                     return json.loads(parsed_message["value"])
    #                 except Exception as e:
    #                     print("⚠️ Failed to parse value:", e)
    #                     return None

    #     except KeyboardInterrupt:
    #         print("👋 Interrupted by user.")
    #     except Exception as e:
    #         print("❌ Error while receiving:", e)
    #     finally:
    #         self.ws.close()
    #         print("🔒 WebSocket closed.")

    # def receive_messages(self, save_path=FILE_PATH):
    #     try:
    #         while True:
    #             message = self.ws.recv()
    #             print("📩 Received:", message)

    #             try:
    #                 parsed_message = json.loads(message)
    #             except json.JSONDecodeError:
    #                 print("⚠️ Skipping non-JSON message")
    #                 continue

    #             # Save to file
    #             mesh_data = []
    #             if os.path.exists(save_path):
    #                 try:
    #                     with open(save_path, 'r') as f:
    #                         mesh_data = json.load(f)
    #                 except json.JSONDecodeError:
    #                     mesh_data = []

    #             mesh_data.append(parsed_message)

    #             with open(save_path, 'w') as f:
    #                 json.dump(mesh_data, f, indent=2)

    #             # Return raw value if it matches the required condition
    #             if parsed_message.get("action") == "msg" and parsed_message.get("type") == "console":
    #                 return parsed_message.get("value")
    #             if parsed_message.get("action") == "msg" and parsed_message.get("type") == "services":
    #                 return parsed_message.get("value")
    #     except Exception as e:
    #         print("❌ Error in receive_messages:", e)
    #         return None


    def receive_messages(self, save_path=FILE_PATH):
        try:
            self.ws.settimeout(5.0)  # increase per recv timeout to 5 seconds

            while True:
                message = self.ws.recv()
                print("📩 Received:", message)

                try:
                    parsed_message = json.loads(message)
                except json.JSONDecodeError:
                    print("⚠️ Skipping non-JSON message")
                    continue

                # Save to file
                mesh_data = []
                if os.path.exists(save_path):
                    try:
                        with open(save_path, 'r') as f:
                            mesh_data = json.load(f)
                    except json.JSONDecodeError:
                        mesh_data = []

                mesh_data.append(parsed_message)

                with open(save_path, 'w') as f:
                    json.dump(mesh_data, f, indent=2)

                if parsed_message.get("action") == "msg" and parsed_message.get("type") == "console":
                    combined_value = parsed_message.get("value", "")
                    start_time = time.time()

                    while time.time() - start_time < 5.0:  # aggregate for up to 5 seconds
                        try:
                            next_msg = self.ws.recv()
                            print("📩 Received:", next_msg)
                            next_parsed = json.loads(next_msg)
                            if (next_parsed.get("action") == "msg" and 
                                next_parsed.get("type") == "console"):
                                combined_value += "\n" + next_parsed.get("value", "")
                            else:
                                pass
                        except websocket._exceptions.WebSocketTimeoutException:
                            break

                    return combined_value

                if parsed_message.get("action") == "msg" and parsed_message.get("type") == "services":
                    return parsed_message.get("value")

        except Exception as e:
            print("❌ Error in receive_messages:", e)
            return None
