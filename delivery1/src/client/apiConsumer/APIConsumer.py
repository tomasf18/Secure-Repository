import base64
import json
import os
import sys
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from constants.return_code import ReturnCode
from utils.signing import sign_document, verify_doc_sign
from utils.files import read_private_key, read_public_key
from utils.encryption.ECDH import ECDH
from utils.encryption.AES import AES
from utils.digest import calculateDigest, verifyDigest
import logging

logging.basicConfig(
    # filename='project.log',
    # filemode='a',
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


    def send_request(self, endpoint: str, method: str, data=None, sessionKey: bytes = None, sessionId: int = None):
        '''Function to send a request to the server'''
        try:
            receivedMessage = None
            if sessionKey:
                messageKey, MACKey = sessionKey[:32], sessionKey[32:]

                logging.debug(f"Sending ({method}) to \'{endpoint}\' in session with sessionKey: {sessionKey}, with data= \"{data}\"")

                ## Create and encrypt Payload
                body = self.encryptPayload(
                    data = data,
                    messageKey = messageKey,
                    MACKey = MACKey
                )
                body["session_id"] = sessionId

                logging.debug(f"Encrypted payload = {body}")
                ## Send Encrypted Payload
                response = requests.request(method, self.rep_address + endpoint, json=body)
                logging.debug(f"Server Response = {response.json()}")

                try:
                    receivedMessage = self.decryptPayload(
                        response = response.json(),
                        messageKey = messageKey,
                        MACKey = MACKey
                    )
                    logging.debug(f"Decrypted Server Response = {receivedMessage}")
                except Exception as e:
                    logging.error(f"Error decrypting server response: {e}")

            else:
                logging.debug("Sending request")
                body = {
                    "data": data
                }
                logging.debug(f"Sending ({method}) to \'{endpoint}\' with data= \"{data}\"")
                response = requests.request(method, self.rep_address + endpoint, json=body)


            ## TODO: adicionar maneira de dar print error 404 (getOrganizationDocumentFile orgservices)
            if response.status_code in [200, 201, 403, 404]:
                return receivedMessage if receivedMessage else response.json()
            else:
                print(f'\nError: {response.status_code} - {response.json()}\n')

        except requests.RequestException as e:
            print(f'\nError: {e}\n')
    

    def encryptPayload(self, data, messageKey, MACKey):
        ## Encrypt data
        if isinstance(data, dict):
            data = json.dumps(data)

        encryptor = AES()
        encryptedData, dataIv = encryptor.encrypt_data(data, messageKey)

        message = {
            "message": base64.b64encode(encryptedData).decode(),
            "iv" : base64.b64encode(dataIv).decode(),
        }

        digest = calculateDigest(encryptedData)
        mac, macIv = encryptor.encrypt_data(digest, MACKey)

        body = {
            "data": message,
            "digest": {
                "mac": base64.b64encode(mac).decode(),
                "iv": base64.b64encode(macIv).decode(),
            }
        }
        return body
    
    def decryptPayload(self, response, messageKey, MACKey):
        encryptor = AES()
        receivedData = response["data"]
        receivedMac = response["digest"]

        ## Decrypt Digest
        receivedDigest = encryptor.decrypt_data(
            base64.b64decode(receivedMac["mac"]),
            base64.b64decode(receivedMac["iv"]),
            MACKey
        )

        encryptedMessage = base64.b64decode(receivedData["message"])
        ## Verify digest of received data
        if ( not verifyDigest(encryptedMessage, receivedDigest) ):
            return None

        ## Decrypt data
        receivedMessage = encryptor.decrypt_data(
            encrypted_data = base64.b64decode(receivedData["message"]),
            iv = base64.b64decode(receivedData["iv"]),
            key = messageKey
        )

        return json.loads(receivedMessage.decode())


    def exchangeKeys(self, private_key: ec.EllipticCurvePrivateKey, data: dict):
        ### HANDSHAKE ###
        KeyDerivation = ECDH()

        # Generate Private key
        session_public_key = KeyDerivation.generate_keys()

        # Create packet made of public key and data
        data = {
            "public_key" : base64.b64encode(session_public_key).decode('utf-8'),
            **data
        }

        ## Generate Signature 
        signature = sign_document(
            data = str(data),
            private_key = private_key
        )
        ## Build Session creation packet
        body = {
            "data": data,
            "digest": base64.b64encode(signature).decode('utf-8')
        }

        ## Send to the server 
        response = requests.request("post", self.rep_address + "/sessions", json=body)
        
        if response.status_code not in [201]:
            logging.error(f"Error: Invalid repository response: {response.json()}")
            sys.exit(ReturnCode.REPOSITORY_ERROR)


        ## verify if signature is from repository
        response = response.json()
        if (not verify_doc_sign(response, self.rep_pub_key)):
            sys.exit(ReturnCode.REPOSITORY_ERROR)


        # If it its, finish calculations
        response_data = response["data"]
        server_key = base64.b64decode(response_data["public_key"])
        derivedKey: bytes = KeyDerivation.generate_shared_secret(server_key)

        return derivedKey, response_data