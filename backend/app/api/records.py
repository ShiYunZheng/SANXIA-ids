from flask import Blueprint, request

from ..api_response import success
from ..auth import require_auth
from ..validation import parse_datetime
from .helpers import positive_int, service


blueprint = Blueprint("records", __name__, url_prefix="/records")


@blueprint.get("")
@require_auth
def records():
    page = positive_int(request, "page", 1)
    page_size = positive_int(request, "pageSize", 20, 200)
    start_at = parse_datetime(request.args.get("startAt"), "startAt")
    end_at = parse_datetime(request.args.get("endAt"), "endAt")
    if start_at and end_at and start_at > end_at:
        from ..errors import ApiError
        raise ApiError("VALIDATION_ERROR", "startAt 不能晚于 endAt", 400)
    return success(service("records").page(page, page_size, start_at, end_at))
