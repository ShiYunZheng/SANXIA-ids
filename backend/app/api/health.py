from pathlib import Path

from flask import Blueprint, current_app

from ..api_response import success
from .helpers import service


blueprint = Blueprint("health", __name__)


@blueprint.get("/health")
def health():
    database = "connected"
    try:
        service("mongo").cx.admin.command("ping")
    except Exception:
        database = "unavailable"
    cascade_model = service("cascade_model")
    model_status = service("detection").model_status()
    modbus_status = service("modbus").status()
    sampling = service("sampling").status()
    payload = {
        "service": "ready",
        "database": database,
        "model": (
            "ready" if cascade_model.ready
            else "available" if cascade_model.resources_available()
            else "unavailable"
        ),
        "models": {"cascade": model_status.get("cascade", model_status), "modbus": modbus_status},
        "sampling": sampling,
        "pipeline": service("pipeline").status(),
    }
    status = 200 if database == "connected" else 503
    return success(payload, status=status)
