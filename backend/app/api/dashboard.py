from flask import Blueprint, request

from ..api_response import success
from ..auth import require_auth
from ..errors import ApiError
from .helpers import service


blueprint = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@blueprint.get("/summary")
@require_auth
def summary():
    return success(service("dashboard").summary())


@blueprint.get("/history")
@require_auth
def history():
    try:
        interval = float(request.args.get("intervalMs", 3600000))
        end = request.args.get("endTimestamp")
        end = float(end) if end is not None else None
        points = int(request.args.get("points", 12))
    except ValueError as error:
        raise ApiError("VALIDATION_ERROR", "时间参数必须为数字", 400) from error
    return success(service("dashboard").history(interval, end, points))


@blueprint.get("/realtime")
@require_auth
def realtime():
    try:
        interval = float(request.args.get("intervalMs", 3600000))
        end = request.args.get("endTimestamp")
        end = float(end) if end is not None else None
        points = int(request.args.get("points", 12))
    except ValueError as error:
        raise ApiError("VALIDATION_ERROR", "时间参数必须为数字", 400) from error
    return success(service("dashboard").realtime(
        interval,
        end,
        points,
        service("pipeline"),
        service("events"),
    ))


@blueprint.get("/components/<name>")
@require_auth
def component(name):
    return success(service("dashboard").component(name))
