import requests
from constants.return_code import ReturnCode
from constants.httpMethod import httpMethod
from utils.encryption.ECC import ECC

class ApiConsumer:
    def __init__(self, rep_pub_key: str):
        self.rep_pub_key = rep_pub_key

    def send_request(self, url: str, method: httpMethod, data=None):
        '''Function to send a request to the server'''
        try:
            signed_data = self.sign_document(data)

            response = requests.request(method.method, url, json=signed_data)

            if (not self.verify_doc_sign(response.json())):
                return

            if response.status_code in [200, 201]:
                print(f'\nResponse: {response.status_code} - {response.json()}\n')
                return response.json()
            else:
                print(f'\nError: {response.status_code} - {response.json()}\n')

        except requests.RequestException as e:
            print(f'\nError: {e}\n')
    

    def sign_document(self, data) -> str:
        return data

    def verify_doc_sign(self, data) -> bool:
        return True
        message = data["message"]
        signature = data["signature"]
        cypher = ECC()

        receivedDigest = cypher.decrypt_data(signature, self.rep_pub_key)
        messageDigest = self.calculateDigest(data=message)

        return receivedDigest == messageDigest

    def calculateDigest(self, data: str) -> str:
        return data
