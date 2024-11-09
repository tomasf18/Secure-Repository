#!/usr/bin/python3

import sys

# Run Startup 
from startup import parse_args, state, save_state

from utils import read_file
from apiConsumer.APIConsumer import ApiConsumer
from constants.httpMethod import httpMethod
from constants.return_code import ReturnCode


'''
Create a session calling the endpoint /sessions/create
rep_create_session <organization> <username> <password> <credentials_file> <session_file>
'''
endpoint = "/sessions/create"

state = parse_args(
    state, 
    positional_args = [
        "organization",
        "username",
        "password",
        "credentials_file",
        "session_file"
    ]
)
url = state["REP_ADDRESS"] + endpoint

pubKey: str | None = read_file(state["credentials_file"])

if pubKey is None:
    sys.exit(ReturnCode.INPUT_ERROR)

apiConsumer = ApiConsumer(
    rep_pub_key = state["REP_PUB_KEY"],
)

data = {
    'organization': state["org_name"],
    'username': state["username"],
    'password': state["password"],
    'credentials': read_file(state["credentials_file"]),
}

result = apiConsumer.send_request(url=url, method=httpMethod.POST, data=data)

if result is None:
    sys.exit(ReturnCode.REPOSITORY_ERROR)

print(result)
sys.exit(ReturnCode.SUCCESS)