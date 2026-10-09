from flask import Blueprint, request

from ..api_response import success
from ..auth import require_auth
from ..errors import ApiError
from .helpers import service

blueprint = Blueprint("validation", __name__, url_prefix="/validation")


@blueprint.post("/compare")
@require_auth
def compare():
    uploaded_file = request.files.get("file")
    if uploaded_file is None or not uploaded_file.filename:
        raise ApiError("FILE_REQUIRED", "请选择要对比的 PCAP、PCAPNG 或原始字节 CSV 文件", 400)
    return success(service("validation").compare_upload(uploaded_file))


@blueprint.post("/association")
@require_auth
def association():
    payload = request.get_json(silent=True) or {}
    window = payload.get("window")
    if not isinstance(window, dict):
        raise ApiError("INVALID_WINDOW", "缺少有效的 standalone 窗口数据", 400)
    label = window.get("predictedLabel") or window.get("predicted_label")
    features = window.get("features")
    if not label:
        raise ApiError("INVALID_WINDOW", "窗口缺少预测标签", 400)
    if not isinstance(features, dict):
        raise ApiError("INVALID_WINDOW", "窗口缺少特征数据", 400)
    force = payload.get("force") is True
    return success(service("validation").associate_window(window, force=force))
