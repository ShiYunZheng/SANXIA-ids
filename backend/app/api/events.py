import json
import queue

from flask import Blueprint, Response, g, request, stream_with_context

from ..api_response import JsonEncoder, success
from ..auth import require_auth
from ..validation import json_body
from .helpers import positive_int, service


blueprint = Blueprint("events", __name__, url_prefix="/events")


@blueprint.get("")
@require_auth
def events():
    return success(service("events").page(
        positive_int(request, "page", 1),
        positive_int(request, "pageSize", 20, 200),
        request.args.get("pipelineRunId") or None,
    ))


@blueprint.get("/judgements")
@require_auth
def judgements():
    limit = positive_int(request, "limit", 5, 20)
    return success(service("events").judgements(limit, service("modbus")))


@blueprint.get("/<event_id>")
@require_auth
def event_detail(event_id):
    return success(service("events").detail(event_id, service("modbus")))

@blueprint.post("/<event_id>/judgement")
@require_auth
def regenerate_event_judgement(event_id):
    return success(service("events").regenerate_judgement(event_id, service("modbus")))


@blueprint.patch("/<event_id>/disposition")
@require_auth
def update_event_disposition(event_id):
    return success(service("events").update_disposition(
        event_id,
        g.identity,
        json_body(request),
        service("modbus"),
    ))

@blueprint.get("/stream")
@require_auth
def event_stream():
    event_service = service("events")
    subscriber = event_service.subscribe()

    @stream_with_context
    def generate():
        try:
            yield ": connected\n\n"
            while True:
                try:
                    event = subscriber.get(timeout=15)
                    yield f"data: {json.dumps(event, cls=JsonEncoder, ensure_ascii=False)}\n\n"
                except queue.Empty:
                    yield ": keep-alive\n\n"
        finally:
            event_service.unsubscribe(subscriber)

    return Response(generate(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
