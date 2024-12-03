from flask import Blueprint
from services.file_service import *

file_blueprint = Blueprint("files", __name__)

# -------------------------------

@file_blueprint.route("/files/<file_handle>", methods=["GET"])
def files(file_handle):
    return download_file(file_handle)