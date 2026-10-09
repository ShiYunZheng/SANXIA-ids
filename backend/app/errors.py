from flask import current_app
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from .api_response import failure


class ApiError(Exception):
    def __init__(self, code, message, status=400, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def handle_api_error(error):
        return failure(error.code, error.message, error.status, error.details)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(_error):
        return failure("FILE_TOO_LARGE", "上传文件超过大小限制", 413)

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return failure("HTTP_ERROR", error.description, error.code)

    @app.errorhandler(Exception)
    def handle_unexpected(error):
        current_app.logger.exception("Unhandled request error", exc_info=error)
        return failure("INTERNAL_ERROR", "服务器内部错误", 500)
