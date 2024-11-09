from flask import Flask, request
from src.server.controllers.organization_controller import organization_blueprint
from src.server.controllers.session_controller import session_blueprint

app = Flask(__name__)

organizations = {}
sessions = {}

app.register_blueprint(organization_blueprint)
app.register_blueprint(session_blueprint)

if __name__ == '__main__':
    app.run(debug=True)