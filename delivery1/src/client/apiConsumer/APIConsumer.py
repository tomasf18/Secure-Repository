import requests
from constants.return_code import ReturnCode
from utils.signing import sign_document, verify_doc_sign


class ApiConsumer:
    def __init__(self, rep_pub_key: str, private_key: str = None):
        self.rep_pub_key = rep_pub_key
        self.private_key = private_key

    def send_request(self, url: str, method: str, data=None, encrypt: bool = False, sign: bool = False):
        '''Function to send a request to the server'''
        try:
            if sign:
                data = sign_document(data)

            response = requests.request(method, url, json=data)

            #if (not self.verify_doc_sign(response.json(), self.rep_pub_key)):
                #return

            if response.status_code in [200, 201]:
                print(f'\nResponse: {response.status_code} - {response.json()}\n')
                return response.json()
            else:
                print(f'\nError: {response.status_code} - {response.json()}\n')

        except requests.RequestException as e:
            print(f'\nError: {e}\n')
