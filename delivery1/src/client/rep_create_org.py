#!/usr/bin/python3

import sys

# Run Startup 
from startup import parse_args, state, save_state

from utils import read_file
from apiConsumer.APIConsumer import ApiConsumer
from constants.httpMethod import httpMethod
from constants.return_code import ReturnCode


'''rep_create_org <organization> <username> <name> <email> <public_key_file>'''
endpoint = "/organizations"

state = parse_args(
    state, 
    positional_args = [
        "organization",
        "username",
        "name",
        "email",
        "public_key_file"
    ]
)

pubKey: str | None = read_file(state["public_key_file"])

if pubKey is None:
    sys.exit(ReturnCode.INPUT_ERROR)

apiConsumer = ApiConsumer(
    url = state["REP_ADDRESS"] + endpoint,
    rep_pub_key = state["REP_PUB_KEY"],
    pub_key = pubKey
)

data = {
    'organization': state["org_name"],
    'username': state["username"],
    'name': state["name"],
    'email': state["email"],
}

result = apiConsumer.send_request(method=httpMethod.POST, data=data)

if result is None:
    sys.exit(ReturnCode.REPOSITORY_ERROR)

print(result)
sys.exit(ReturnCode.SUCCESS)