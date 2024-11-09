import requests
import cmd
from return_code import ReturnCode

class Client(cmd.Cmd):
    intro = 'Welcome to the client shell. Type help or ? to list commands.\n'
    prompt = '(client) '
    
    def send_request(self, url, method, data=None):
        '''Function to send a request to the server'''
        try:
            if method == 'POST':
                response = requests.post(url, json=data)
            elif method == 'GET':
                response = requests.get(url)

            if response.status_code in [200, 201]: # Success
                print(f'\nResponse: {response.status_code} - {response.json()}\n')
                return ReturnCode.SUCCESS
            
            elif 400 <= response.status_code < 500: # Client error (Input)
                print(f'\nError: {response.status_code} - {response.json()}\n')

            else: # Server error (Repository)
                print(f'\nError: {response.status_code} - {response.json()}\n')

        except requests.RequestException as e:
            print(f'\nError: {e}\n')
    
    def do_rep_create_org(self, arg):
        '''rep_create_org <organization> <username> <name> <email> <public_key_file> - Create an organization calling the endpoint /organizations/create'''
        args = arg.split()
        
        if len(args) != 5:
            print('Usage: rep_create_org <organization> <username> <name> <email> <public key file>')
            return
        
        org_name, username, name, email, public_key_file = args
        
        data = {
            'organization': org_name,
            'username': username,
            'name': name,
            'email': email,
            'public_key_file': public_key_file
        }
        
        url = 'http://localhost:5000/organizations'
        return self.send_request(url, 'POST', data)
            
    def do_rep_list_orgs(self, arg):
        '''rep_list_orgs - List all organizations calling the endpoint /organizations/list'''
        url = 'http://localhost:5000/organizations'
        self.send_request(url, 'GET')
    
    def do_rep_create_session(self, arg):
        '''rep_create_session <organization> <username> <password> <cardentials_file> <session_file> - Create a session calling the endpoint /sessions/create'''
        args = arg.split()
        
        if len(args) != 5:
            print('Usage: rep_create_session <organization> <username> <password> <cardentials_file> <session_file>')
            return
        
        org_name, username, password, cardentials_file, session_file = args
        
        data = {
            'organization': org_name,
            'username': username,
            'password': password,
            'cardentials_file': cardentials_file,
            'session_file': session_file
        }
        
        url = 'http://localhost:5000/sessions'
        self.send_request(url, 'POST', data)
    
    def do_exit(self, arg):
        '''Exit the client shell'''
        print('Exiting the client shell...')
        return "exit"

    def postcmd(self, stop, line):
        """
        Post command handling:
        return: True to stop the CLI
                False to continue running
        """
        return stop == "exit"

if __name__ == '__main__':
    Client().cmdloop()