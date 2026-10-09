from flask import Blueprint, g, request

from ..api_response import success
from ..auth import create_access_token, require_auth
from ..validation import json_body, required_text
from .helpers import service


blueprint = Blueprint("auth", __name__, url_prefix="/auth")


@blueprint.post("/login")
def login():
    data = json_body(request)
    user = service("users").authenticate(required_text(data, "username", 64), required_text(data, "password", 256))
    return success({"accessToken": create_access_token(user)})


@blueprint.get("/me")
@require_auth
def me():
    return success(service("users").get_by_identity(g.identity))
