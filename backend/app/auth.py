from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, request

from .errors import ApiError


def create_access_token(user):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["_id"]),
        "username": user["username"],
        "role": int(user.get("role", 2)),
        "iat": now,
        "exp": now + timedelta(minutes=current_app.config["JWT_EXPIRES_MINUTES"]),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET"], algorithm="HS256")


def decode_access_token(token):
    try:
        return jwt.decode(token, current_app.config["JWT_SECRET"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError as error:
        raise ApiError("TOKEN_EXPIRED", "登录已过期，请重新登录", 401) from error
    except jwt.InvalidTokenError as error:
        raise ApiError("INVALID_TOKEN", "无效的访问令牌", 401) from error


def require_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise ApiError("AUTH_REQUIRED", "需要 Bearer 访问令牌", 401)
        g.identity = decode_access_token(token)
        return handler(*args, **kwargs)

    return wrapped
