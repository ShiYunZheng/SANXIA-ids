import json
import queue

from flask import Blueprint, Response, request, stream_with_context

from ..api_response import JsonEncoder, success
from ..auth import require_auth
from ..errors import ApiError
from ..validation import json_body
from .helpers import positive_int, service


blueprint = Blueprint("pipeline", __name__, url_prefix="/pipeline")


def _status():
    return {**service("pipeline").status(), "sampling": service("sampling").status()}


@blueprint.get("")
@require_auth
def status():
    return success(_status())


@blueprint.get("/sources")
@require_auth
def sources():
    return success(service("sampling").sources())


@blueprint.post("/start")
@require_auth
def start():
    payload = request.get_json(silent=True) or {}
    persist = payload.get("persist", True)
    if not isinstance(persist, bool):
        raise ApiError("INVALID_PERSIST_MODE", "persist 必须为布尔值", 400)
    service("pipeline").start(persist=persist)
    return success(_status())


@blueprint.post("/stop")
@require_auth
def stop():
    service("pipeline").stop()
    return success(_status())


@blueprint.post("/source")
@require_auth
def switch_source():
    source = json_body(request).get("source")
    if source not in {"csv", "pcap", "replay", "interface"}:
        raise ApiError("INVALID_SAMPLE_SOURCE", "采样源必须是 csv、pcap、replay 或 interface", 400)

    options = {}
    machine_name = json_body(request).get("machineName")
    if machine_name is not None:
        options["machine_name"] = machine_name
    if source == "interface":
        options["interface"] = json_body(request).get("interface")
    service("pipeline").switch_source(source, **options)
    return success(_status())


@blueprint.post("/pcap")
@require_auth
def upload_pcap():
    uploaded = request.files.get("file")
    if uploaded is None:
        raise ApiError("FILE_REQUIRED", "请选择要上传的 PCAP 文件", 400)
    source = str(request.form.get("source") or "pcap").strip().lower()
    if source not in {"pcap", "replay"}:
        raise ApiError("INVALID_SAMPLE_SOURCE", "PCAP 上传源必须是 pcap 或 replay", 400)
    stored = service("sampling").store_pcap(uploaded)
    machine_name = str(request.form.get("machineName") or "").strip() or None
    service("pipeline").switch_source(
        source, pcap_path=stored["path"], pcap_name=stored["name"], machine_name=machine_name,
    )
    return success({**_status(), "upload": {key: value for key, value in stored.items() if key != "path"}})


@blueprint.get("/modbus/windows")
@require_auth
def modbus_windows():
    return success(service("realtime_inference").latest(positive_int(request, "limit", 5, 100)))


@blueprint.get("/alerts")
@require_auth
def runtime_alerts():
    run_id = str(request.args.get("runId") or "").strip() or None
    limit = positive_int(request, "limit", 100, 200)
    pipeline = service("pipeline")
    items = pipeline.alerts(run_id, limit)
    return success({
        "items": items,
        "total": pipeline.alert_total(run_id),
        "returned": len(items),
        "runId": run_id,
    })


@blueprint.get("/alerts/stream")
@require_auth
def runtime_alert_stream():
    pipeline = service("pipeline")
    subscriber = pipeline.subscribe_alerts()

    @stream_with_context
    def generate():
        try:
            yield ": connected\n\n"
            while True:
                try:
                    item = subscriber.get(timeout=15)
                    yield f"data: {json.dumps(item, cls=JsonEncoder, ensure_ascii=False)}\n\n"
                except queue.Empty:
                    yield ": keep-alive\n\n"
        finally:
            pipeline.unsubscribe_alerts(subscriber)

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@blueprint.get("/modbus/stream")
@require_auth
def modbus_stream():
    inference = service("realtime_inference")
    subscriber = inference.subscribe()

    @stream_with_context
    def generate():
        try:
            yield ": connected\n\n"
            while True:
                try:
                    item = subscriber.get(timeout=15)
                    yield f"data: {json.dumps(item, cls=JsonEncoder, ensure_ascii=False)}\n\n"
                except queue.Empty:
                    yield ": keep-alive\n\n"
        finally:
            inference.unsubscribe(subscriber)

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
