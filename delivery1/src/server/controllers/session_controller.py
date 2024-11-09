from flask import Blueprint, request
from ..services.session_service import *

session_blueprint = Blueprint('sessions', __name__)

@session_blueprint.route('/sessions', methods=['POST'])
def sessions():
    data = request.json
    return create_session(data)