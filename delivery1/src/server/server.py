from flask import Flask
from controllers.organization_controller import organization_blueprint
from controllers.session_controller import session_blueprint
from controllers.file_controller import file_blueprint

app = Flask(__name__)

app.register_blueprint(organization_blueprint)
app.register_blueprint(session_blueprint)
app.register_blueprint(file_blueprint)

if __name__ == '__main__':
    app.run(debug=True)