from flask import current_app

from ..errors import ApiError


def service(name):
    return current_app.extensions["sanxia_services"][name]


def positive_int(request, name, default, maximum=None):
    raw_value = request.args.get(name, default)
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as error:
        raise ApiError("VALIDATION_ERROR", f"{name} 必须为整数", 400, {"field": name}) from error
    if value < 1 or (maximum is not None and value > maximum):
        message = f"{name} 必须在 1 到 {maximum} 之间" if maximum else f"{name} 必须大于 0"
        raise ApiError("VALIDATION_ERROR", message, 400, {"field": name})
    return value
