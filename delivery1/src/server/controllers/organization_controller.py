from flask import Blueprint, request
from services.organization_service import *

organization_blueprint = Blueprint("organizations", __name__)


@organization_blueprint.route("/organizations", methods=["GET", "POST"])
def organizations():
    print(request.data)
    if request.method == "GET":
        return list_organizations()
    if request.method == "POST":
        data = request.json
        return create_organization(data)


@organization_blueprint.route(
    "/organizations/<organization_name>/subjects", methods=["GET", "POST"]
)
def organization_subjects(organization_name):
    print(request)
    if request.method == "GET":
        return list_organization_subjects(organization_name)


@organization_blueprint.route(
    "/organizations/<organization_name>/subjects/<subject_name>",
    methods=["GET", "PUT", "DELETE"],
)
def organization_subject(organization_name, subject_name):
    print(request)
    if request.method == "GET":
        return get_organization_subject(organization_name, subject_name)
