from flask import Blueprint, g, request

from ..api_response import success
from ..auth import require_auth
from ..validation import json_body, required_text
from .helpers import service


blueprint = Blueprint("users", __name__, url_prefix="/users")


@blueprint.get("")
@require_auth
def list_users():
    role = request.args.get("role")
    return success(service("users").list_users(int(role) if role is not None else None))


@blueprint.post("")
@require_auth
def create_user():
    data = json_body(request)
    data["username"] = required_text(data, "username", 64)
    data["password"] = required_text(data, "password", 256)
    return success(service("users").create(g.identity, data), status=201)


@blueprint.patch("/<user_id>")
@require_auth
def update_user(user_id):
    return success(service("users").update(g.identity, user_id, json_body(request)))
