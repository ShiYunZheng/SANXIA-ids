import json
from datetime import date, datetime, timezone
from enum import Enum

import numpy as np
from bson import ObjectId
from flask import Response


class JsonEncoder(json.JSONEncoder):
    def default(self, value):
        if isinstance(value, ObjectId):
            return str(value)
        if isinstance(value, (datetime, date)):
            current = value
            if isinstance(value, datetime) and value.tzinfo is None:
                current = value.replace(tzinfo=timezone.utc)
            return current.isoformat()
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, np.generic):
            return value.item()
        if isinstance(value, np.ndarray):
            return value.tolist()
        return super().default(value)


def _response(payload, status=200, headers=None, mimetype="application/json"):
    return Response(
        json.dumps(payload, cls=JsonEncoder, ensure_ascii=False),
        status=status,
        headers=headers,
        mimetype=mimetype,
    )


def success(data=None, status=200, headers=None):
    return _response({"data": {} if data is None else data}, status, headers)


def failure(code, message, status=400, details=None, headers=None):
    error = {"code": code, "message": message}
    if details:
        error["details"] = details
    return _response({"error": error}, status, headers)
