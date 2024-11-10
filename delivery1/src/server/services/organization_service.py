from dao.organization_dao import organizations
import json

def list_organizations():
    '''Handles GET requests to /organizations'''
    return json.dumps(organizations), 200

def create_organization(data):
    '''Handles POST requests to /organizations'''
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