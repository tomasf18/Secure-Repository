import requests
from constants.return_code import ReturnCode
from constants.httpMethod import httpMethod

class ApiConsumer:
    def __init__(self, rep_pub_key: str, pub_key: str = None):
        self.rep_pub_key = rep_pub_key
        self.pub_key = pub_key

    def send_request(self, url: str, method: httpMethod, data=None):
        '''Function to send a request to the server'''
        try:
            response = requests.request(method.method, url, json=data)

            if response.status_code in [200, 201]:
                print(f'\nResponse: {response.status_code} - {response.json()}\n')
                return response.json()
            else:
                print(f'\nError: {response.status_code} - {response.json()}\n')

        except requests.RequestException as e:
            print(f'\nError: {e}\n')