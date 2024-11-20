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
    db_session = g.db_session
    data = request.json
    if request.method == 'GET':
<<<<<<< Updated upstream
        return list_organization_subjects(organization_name, db_session)
=======
        return list_organization_subjects(organization_name, data, db_session)
    elif request.method == 'POST':
        return add_organization_subject(organization_name, data, db_session)
>>>>>>> Stashed changes

@organization_blueprint.route('/organizations/<organization_name>/subjects/<username>', methods=['GET', 'PUT', 'DELETE'])
def organization_subject(organization_name, username):
    db_session = g.db_session
    if request.method == 'GET':
        return get_organization_subject(organization_name, username, db_session)
    elif request.method == 'PUT':
        return activate_organization_subject(organization_name, username, db_session)
    elif request.method == 'DELETE':
        return suspend_organization_subject(organization_name, username, db_session)
