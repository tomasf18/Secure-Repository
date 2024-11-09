from flask import Flask, request
import json

app = Flask(__name__)

organizations = {}
sessions = {}

@app.route('/organizations/list', methods=['GET'])
def org_list():
    return json.dumps(organizations)

@app.route('/organizations/create', methods=['POST'])
def org_create():
    data = request.json
    org_name = data.get('organization')
    
    if org_name in organizations:
        return json.dumps(f'Organization {org_name} already exists'), 400
    
    # simulation of creating an organization
    organizations[org_name] = {
        'username': data.get('username'),
        'name': data.get('name'),
        'email': data.get('email'),
        'public_key_file': data.get('public_key_file')
    }
    
    return json.dumps(f'Organization {org_name} created successfully'), 201

@app.route('/sessions/create', methods=['POST'])
def session_create():
    data = request.json
    org_name = data.get('organization')
    
    if org_name not in organizations:
        return json.dumps(f'Organization {org_name} does not exist'), 404
    
    # simulation of creating a session
    session_id = len(sessions) + 1
    sessions[session_id] = {
        'organization': org_name,
        'username': data.get('username'),
        'password': data.get('password'),
        'cardentials_file': data.get('cardentials_file'),
        'session_file': data.get('session_file')
    }
    
    return json.dumps(f'Session {session_id} created successfully'), 201

if __name__ == '__main__':
    app.run(debug=True)