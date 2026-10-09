from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import DuplicateKeyError, PyMongoError
from werkzeug.security import check_password_hash, generate_password_hash

from ..constants import ROLE_ADMIN, ROLE_USER, ROLE_USER_REGISTER
from ..errors import ApiError


def public_user(user):
    if not user:
        return None
    return {key: value for key, value in user.items() if key != "password"}


class UserService:
    def __init__(self, repository):
        self.repository = repository

    def authenticate(self, username, password):
        try:
            user = self.repository.find_by_username(username, include_password=True)
        except PyMongoError as error:
            raise ApiError("DATABASE_UNAVAILABLE", "数据库服务未启动，请先启动 MongoDB", 503) from error
        if not user or not check_password_hash(user.get("password", ""), password):
            raise ApiError("INVALID_CREDENTIALS", "用户名或密码错误", 401)
        return user

    def get_by_identity(self, identity):
        user = self._find(identity["sub"])
        if not user:
            raise ApiError("USER_NOT_FOUND", "用户不存在", 404)
        return public_user(user)

    def list_users(self, role=None):
        if role is not None and role not in {ROLE_ADMIN, ROLE_USER_REGISTER, ROLE_USER}:
            raise ApiError("VALIDATION_ERROR", "无效的用户角色", 400)
        return [public_user(user) for user in self.repository.list(role)]

    def create(self, actor, data):
        actor_user = self.get_by_identity(actor)
        if not actor_user.get("rights", {}).get("register_user"):
            raise ApiError("FORBIDDEN", "没有注册用户权限", 403)
        role = data.get("role", ROLE_USER)
        if role not in {ROLE_ADMIN, ROLE_USER_REGISTER, ROLE_USER}:
            raise ApiError("VALIDATION_ERROR", "无效的用户角色", 400, {"field": "role"})
        rights = {
            "delete_record": role == ROLE_ADMIN,
            "register_user": role in {ROLE_ADMIN, ROLE_USER_REGISTER},
        }
        user = {
            "username": data["username"],
            "password": generate_password_hash(data["password"], method="pbkdf2:sha256", salt_length=24),
            "email": data.get("email", ""),
            "firstname": data.get("firstname", ""),
            "lastname": data.get("lastname", ""),
            "role": role,
            "rights": rights,
        }
        try:
            result = self.repository.insert(user)
        except DuplicateKeyError as error:
            raise ApiError("USERNAME_EXISTS", "用户名已存在", 409) from error
        user["_id"] = result.inserted_id
        return public_user(user)

    def update(self, actor, user_id, data):
        target = self._find(user_id)
        if not target:
            raise ApiError("USER_NOT_FOUND", "用户不存在", 404)
        actor_user = self.get_by_identity(actor)
        is_admin = actor_user.get("role") == ROLE_ADMIN
        if str(actor_user["_id"]) != str(target["_id"]) and not is_admin:
            raise ApiError("FORBIDDEN", "只能修改自己的资料", 403)
        allowed = {"email", "firstname", "lastname", "password"}
        if is_admin:
            allowed.add("role")
        fields = {key: value for key, value in data.items() if key in allowed and value is not None}
        if "password" in fields:
            if not isinstance(fields["password"], str) or len(fields["password"]) < 8:
                raise ApiError("VALIDATION_ERROR", "密码至少需要 8 个字符", 400, {"field": "password"})
            fields["password"] = generate_password_hash(fields["password"], method="pbkdf2:sha256", salt_length=24)
        if "role" in fields:
            if fields["role"] not in {ROLE_ADMIN, ROLE_USER_REGISTER, ROLE_USER}:
                raise ApiError("VALIDATION_ERROR", "无效的用户角色", 400, {"field": "role"})
            fields["rights"] = {
                "delete_record": fields["role"] == ROLE_ADMIN,
                "register_user": fields["role"] in {ROLE_ADMIN, ROLE_USER_REGISTER},
            }
        if fields:
            self.repository.update(target["_id"], fields)
        return self.get_by_identity({"sub": str(target["_id"])})

    def _find(self, user_id):
        try:
            return self.repository.find_by_id(ObjectId(user_id))
        except (InvalidId, TypeError):
            raise ApiError("INVALID_USER_ID", "无效的用户 ID", 400)
