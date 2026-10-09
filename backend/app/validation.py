from datetime import datetime, timezone

from .errors import ApiError


def json_body(request):
    if not request.is_json:
        raise ApiError("INVALID_JSON", "请求体必须为 JSON", 400)
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise ApiError("INVALID_JSON", "请求体必须为 JSON 对象", 400)
    return value


def required_text(data, name, max_length=255):
    value = data.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ApiError("VALIDATION_ERROR", f"{name} 不能为空", 400, {"field": name})
    value = value.strip()
    if len(value) > max_length:
        raise ApiError("VALIDATION_ERROR", f"{name} 长度不能超过 {max_length}", 400, {"field": name})
    return value


def pagination(request, max_page_size=100):
    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("pageSize", 20))
    except (TypeError, ValueError) as error:
        raise ApiError("VALIDATION_ERROR", "分页参数必须为整数", 400) from error
    if page < 1 or page_size < 1 or page_size > max_page_size:
        raise ApiError("VALIDATION_ERROR", f"page 必须大于 0，pageSize 必须在 1-{max_page_size} 之间", 400)
    return page, page_size


def parse_datetime(value, field):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ApiError("VALIDATION_ERROR", f"{field} 必须为 ISO 8601 时间", 400, {"field": field}) from error
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
