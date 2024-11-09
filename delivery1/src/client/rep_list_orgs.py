#!/usr/bin/python3
import sys

# Run Startup 
from startup import parse_args, state, save_state

from utils import read_file
from apiConsumer.APIConsumer import ApiConsumer
from constants.httpMethod import httpMethod
from constants.return_code import ReturnCode


'''rep_list_orgs - List all organizations calling the endpoint /organizations/list'''
endpoint = "/organizations/list"
state = parse_args(state)
url = state["REP_ADDRESS"] + endpoint

apiConsumer = ApiConsumer(
    rep_pub_key = state["REP_PUB_KEY"],
)

result = apiConsumer.send_request(url=url, method=httpMethod.GET)

if result is None:
    sys.exit(ReturnCode.REPOSITORY_ERROR)

print(result)
sys.exit(ReturnCode.SUCCESS)