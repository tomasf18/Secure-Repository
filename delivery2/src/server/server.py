from flask import Flask, g

from dao.Database import Database

from controllers.organization_controller import organization_blueprint
from controllers.session_controller import session_blueprint
from controllers.file_controller import file_blueprint

app = Flask(__name__)

# Initialize the Database object
db = Database()
print(" ================ Empty Database created! ================ ")

# Register blueprints for all controllers
app.register_blueprint(organization_blueprint)
app.register_blueprint(session_blueprint)
app.register_blueprint(file_blueprint)

# Add a function to load the session before every request
@app.before_request
def before_request():
    db.create_session()
    g.db_session = db.get_session()  # Store the session in the global context (g)

# Add a function to close the session after each request
@app.teardown_request
def teardown_request(exception):
    db.close_session()  # Close the session at the end of the request

if __name__ == '__main__':
    app.run(debug=True)
