from flask import Blueprint, request, g
from services.session_service import *

session_blueprint = Blueprint('sessions', __name__)

# a chave de sessao é encriptada antes de chamar a funcao da base de dados
@session_blueprint.route('/sessions', methods=['POST'])
def sessions():
    db_session = g.db_session
    data = request.json
    return create_session(data, db_session)