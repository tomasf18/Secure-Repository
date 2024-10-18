from flask import Flask
import json

app = Flask(__name__)

organizations = {}

@app.route("/organization/list")
def org_list():
    return json.dumps(organizations)

#@app.route("/organization/create")
#...
