from flask import Blueprint

from ..api_response import success
from ..auth import require_auth
from .helpers import service


blueprint = Blueprint("attack", __name__, url_prefix="/attack")


@blueprint.get("/samples")
@require_auth
def samples():
    return success(service("attack").samples())
