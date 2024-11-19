import requests
from cryptography.hazmat.primitives import serialization
from constants.return_code import ReturnCode
from utils.signing import sign_document, verify_doc_sign
from utils.files import read_private_key
from utils.encryption.ECDH import ECDH
from utils.encryption.AES import AES
from utils.digest import calculateDigest, verifyDigest


class ApiConsumer:
    def __init__(
            self,
            rep_address: str,
            rep_pub_key: str,
        ):
        self.rep_pub_key = rep_pub_key
        self.rep_address = rep_address


    def send_request(self, endpoint: str, method: str, data=None, sessionKey: bytes = None):
        '''Function to send a request to the server'''
        try:
            if sessionKey:
                messageKey, MACKey = sessionKey[:32], sessionKey[32:]

                print("\ndata: data\n")

                ## Create and encrypt Payload
                body = self.encryptPayload(
                    message = data,
                    messageKey = messageKey,
                    MACKey = MACKey
                )


                print(f"\nEncrypted payload = {body}\n")
                ## Send Encrypted Payload
                response = requests.request(method, self.rep_address + endpoint, json=body)
                print(f"\nServer Response = {response.json()}\n")

                receivedMessage = self.decryptPayload(
                    response = response.json(),
                    messageKey = messageKey,
                    MACKey = MACKey
                )

            else:
                print("Sending request")
                body = {
                    "data": data
                }
                response = requests.request(method, self.rep_address + endpoint, json=body)


            if response.status_code in [200, 201]:
                print(f'\nResponse: {response.status_code} - {response.json()}\n')
                return receivedMessage if receivedMessage else response.json()
            else:
                print(f'\nError: {response.status_code} - {response.json()}\n')

        except requests.RequestException as e:
            print(f'\nError: {e}\n')
    

    def encryptPayload(self, data, messageKey, MACKey):
        ## Encrypt data
        encryptor = AES()
        encryptedData, dataIv = encryptor.encrypt_data(data, messageKey)

        message = {
            "message": encryptedData,
            "iv" : dataIv,
        }

        digest = calculateDigest(encryptedData)
        mac, macIv = encryptor.encrypt_data(digest, MACKey)

        body = {
            "data": message,
            "digest": {
                "mac": mac,
                "iv": macIv,
            }
        }
        return body
    
    def decryptPayload(self, response, messageKey, MACKey):
        encryptor = AES()
        receivedData = response["data"]
        receivedMac = response["digest"]

        ## Decrypt Digest
        receivedDigest = encryptor.decrypt_data(
            receivedMac["mac"],
            receivedMac["iv"],
            MACKey
        )

        ## Verify digest of received data
        if ( not verifyDigest(receivedData, receivedDigest) ):
            return None
        
        ## Decrypt data
        receivedMessage = encryptor.decrypt_data(
            encrypted_data=receivedData["message"],
            iv = receivedData["iv"],
            key = messageKey
        )

        return receivedMessage


    def exchangeKeys(self, credentials: str, password: str):
        private_key = serialization.load_pem_private_key(
            data=credentials,
            password=password
        )

        ### HANDSHAKE ###
        KeyDerivation = ECDH()

        # Generate Private key
        session_public_key = KeyDerivation.generate_keys()

        # Create packet made of (public key)
        data = {
            "public_key" : str(session_public_key)
        }
        # Write public key to send and encrypted digest
        body = {
            "data": data,
            "digest": sign_document(
                data = str(data),
                key = private_key,
                password = password
            )
        }

        # Send to the server 
        response = requests.request("post", self.rep_address + "/sessions", json=body)
        

        # verify if signature is valid
        response = response.json()
        if (not verify_doc_sign(response, self.rep_pub_key)):
            return None

        # If it its, finish calculations
        server_key = response["public_key"]
        derivedKey: bytes = KeyDerivation.generate_shared_secret(server_key)

        return derivedKey