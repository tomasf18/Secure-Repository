import sys
import json
import base64
import logging
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from utils.session_utils import exchange_keys as exchange_keys_utils
from utils.session_utils import encrypt_payload as encrypt_payload_utils
from utils.session_utils import decrypt_payload as decrypt_payload_utils

logging.basicConfig(
    filename='project.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

class ApiConsumer:
    def __init__(
            self,
            rep_address: str,
            rep_pub_key: str,
        ):
        self.rep_pub_key = serialization.load_pem_public_key(rep_pub_key.encode())
        self.rep_address = rep_address

# -------------------------------

    def send_request(self, endpoint: str, method: str, data=None, sessionKey: bytes = None, sessionId: int = None):
        """Send request to the repository
        

        Args:
            endpoint (str): Endpoint to send the request 
            method (str): Method to send the request
            data (_type_, optional): Data to be sent. Defaults to None.
            sessionKey (bytes, optional): Session key to encrypt the data. Defaults to None.
            sessionId (int, optional): Session ID to be sent. Defaults to None.

        Returns:
            dict: Response from the server
        """
        
        try:
            received_message = None
            
            if sessionKey:
                encryption_key, integrity_key = sessionKey[:32], sessionKey[32:]

                logging.debug(f"Sending ({method}) to \'{endpoint}\' in session with sessionKey: {sessionKey}, with data= \"{data}\"")

                # Create and encrypt Payload
                body = self.encrypt_payload(
                    data = data,
                    encryption_key = encryption_key,
                    integrity_key = integrity_key
                )
                body["session_id"] = sessionId

                logging.debug(f"Encrypted payload = {body}")
                
                # Send Encrypted Payload
                response = requests.request(method, self.rep_address + endpoint, json=body)
                logging.debug(f"Server Response = {response.json()}")

                try:
                    received_message = self.decrypt_payload(
                        response=response.json(),
                        encryption_key=encryption_key,
                        integrity_key=integrity_key
                    )
                    logging.debug(f"Decrypted Server Response = {received_message}")
                except Exception as e:
                    logging.error(f"Error decrypting server response: {e}")

            else:
                logging.debug("Sending request")
                body = {
                    "data": data
                }
                logging.debug(f"Sending ({method}) to \'{endpoint}\' with data= \"{data}\"")
                final_endpoint = self.rep_address + endpoint
                response = requests.request(method, final_endpoint, json=body)


            ## TODO: adicionar maneira de dar print error 404 (getOrganizationDocumentFile orgservices)
            if response.status_code in [200, 201, 403, 404]:
                return received_message if received_message else response.json()
            else:
                print(f'\nError: {response.status_code} - {response.json()}\n')

        except requests.RequestException as e:
            print(f'\nError: {e}\n')

# -------------------------------

    def exchange_keys(self, private_key: ec.EllipticCurvePrivateKey, data: dict):
        return exchange_keys_utils(private_key, data, self.rep_address, self.rep_pub_key)
    
# -------------------------------

    def encrypt_payload(self, data, encryption_key, integrity_key):
        return encrypt_payload_utils(data, encryption_key, integrity_key)

# -------------------------------
    
    def decrypt_payload(self, response, encryption_key, integrity_key):
        return decrypt_payload_utils(response, encryption_key, integrity_key)