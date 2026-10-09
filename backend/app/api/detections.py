from flask import Blueprint, request

from ..api_response import success
from ..auth import require_auth
from ..errors import ApiError
from .helpers import service


blueprint = Blueprint("detections", __name__, url_prefix="/detections")


@blueprint.post("")
@require_auth
def detect():
    uploaded_file = request.files.get("file")
    if uploaded_file is None or not uploaded_file.filename:
        raise ApiError("FILE_REQUIRED", "请选择 CSV 文件", 400)
    result = service("detection").detect_upload(uploaded_file)
    service("records").insert_detection(result["labels"])
    return success(result)


@blueprint.get("/metrics")
@require_auth
def detection_metrics():
    return success(service("detection").get_metrics())

