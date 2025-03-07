import logging
import sys
import requests

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from utils.constants.return_code import ReturnCode
from utils.client_session_utils import exchange_keys as exchange_keys_utils
from utils.client_session_utils import encrypt_payload as encrypt_payload_utils
from utils.client_session_utils import decrypt_payload as decrypt_payload_utils
from utils.client_session_utils import exchange_anonymous_keys as exchange_anonymous_keys_utils
from utils.client_session_utils import encrypt_anonymous as encrypt_anonymous_utils
from utils.client_session_utils import decrypt_anonymous as decrypt_anonymous_utils
from utils.client_session_utils import anonymous_request
from utils.utils import convert_str_to_bytes

logging.basicConfig(
    filename='project.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

logger = logging.getLogger()

class ApiConsumer:
    def __init__(
            self,
            rep_address: str,
            rep_pub_key: bytes,
        ):
        self.rep_pub_key = serialization.load_pem_public_key(rep_pub_key)
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

                logging.debug(f"Sending ({method}) to \'{endpoint}\' in session with sessionKey: {sessionKey}, with (decrypted) payload: \"{data}\"")

                # Create and encrypt Payload
                body = self.encrypt_payload(
                    data=data,
                    encryption_key=encryption_key,
                    integrity_key=integrity_key
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
                    received_message = response.json()
                    logging.debug(f"Error decrypting server response: {e}")

            else:
                                
                response, received_message = anonymous_request(self.rep_pub_key, method, self.rep_address, endpoint, data)

            logging.debug("Response.json was: " , response.json())
            logging.debug("Received message was: ", received_message)
            
            return received_message

        except requests.RequestException as e:
            print(f'Error: Failed to connect to the server!')
            sys.exit(ReturnCode.INPUT_ERROR)

# -------------------------------

    def exchange_keys(self, private_key: ec.EllipticCurvePrivateKey, data: dict):
        return exchange_keys_utils(private_key, data, self.rep_address, self.rep_pub_key)
    
# -------------------------------

    def encrypt_payload(self, data, encryption_key, integrity_key):
        return encrypt_payload_utils(data, encryption_key, integrity_key)

# -------------------------------
    
    def decrypt_payload(self, response, encryption_key, integrity_key):
        return decrypt_payload_utils(response, encryption_key, integrity_key)
    
# -------------------------------
    
    def exchange_anonymous_keys(self, endpoint, method):
        return exchange_anonymous_keys_utils(self.rep_address, endpoint, method, self.rep_pub_key)
    
# -------------------------------

    def encrypt_anonymous(self, data, encryption_key, client_ephemeral_public_key):
        return encrypt_anonymous_utils(data, encryption_key, client_ephemeral_public_key)
    
# -------------------------------
    
    def decrypt_anonymous(self, data, encryption_key, iv):
        return decrypt_anonymous_utils(data, encryption_key, iv)
    