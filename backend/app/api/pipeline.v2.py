from flask import Blueprint, request

from ..api_response import success
from ..auth import require_auth
from ..validation import json_body
from .helpers import service


blueprint = Blueprint("pipeline", __name__, url_prefix="/pipeline")


def _status():
    return {**service("pipeline").status(), "sampling": service("sampling").status()}


@blueprint.get("")
@require_auth
def status():
    return success(_status())


@blueprint.post("/start")
@require_auth
def start():
    service("pipeline").start()
    return success(_status())


@blueprint.post("/stop")
@require_auth
def stop():
    service("pipeline").stop()
    return success(_status())


@blueprint.post("/source")
@require_auth
def source():
    selected = json_body(request).get("source")
    service("pipeline").switch_source(selected)
    return success(_status())
