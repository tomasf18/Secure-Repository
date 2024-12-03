from flask import Blueprint, request, g
from services.session_service import *

session_blueprint = Blueprint("sessions", __name__)

# -------------------------------

# The session key is encrypted before calling the database function
@session_blueprint.route('/sessions', methods=['POST'])
def sessions():
    db_session = g.db_session
    data = request.json
    return create_session(data, db_session)