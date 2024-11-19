from flask import Blueprint, request, g
from services.organization_service import *

organization_blueprint = Blueprint("organizations", __name__)


@organization_blueprint.route("/organizations", methods=["GET", "POST"])
def organizations():
    db_session = g.db_session
    if request.method == 'GET':
        return list_organizations(db_session)
    if request.method == 'POST':
        data = request.json
        return create_organization(data, db_session)

@organization_blueprint.route('/organizations/<organization_name>/subjects', methods=['GET', 'POST'])
def organization_subjects(organization_name):
    if request.method == 'GET':
        return list_organization_subjects(organization_name)

@organization_blueprint.route('/organizations/<organization_name>/subjects/<username>', methods=['GET', 'PUT', 'DELETE'])
def organization_subject(organization_name, username):
    if request.method == 'GET':
        return get_organization_subject(organization_name, username)
