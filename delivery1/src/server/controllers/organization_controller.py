from flask import Blueprint, request
from services.organization_service import *

organization_blueprint = Blueprint('organizations', __name__)

@organization_blueprint.route('/organizations', methods=['GET', 'POST'])
def organizations():
    if request.method == 'GET':
        return list_organizations()
    if request.method == 'POST':
        data = request.json
        return create_organization(data)