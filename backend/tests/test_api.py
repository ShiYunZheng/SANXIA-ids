import pytest

from bson import ObjectId
from werkzeug.security import generate_password_hash

from app import create_app


class FakeUsers:
    user = {
        "_id": ObjectId(),
        "username": "admin",
        "password": generate_password_hash("secret"),
        "role": 0,
        "rights": {"register_user": True, "delete_record": True},
    }

    def authenticate(self, username, password):
        if username != "admin" or password != "secret":
            from app.errors import ApiError
            raise ApiError("INVALID_CREDENTIALS", "用户名或密码错误", 401)
        return self.user

    def get_by_identity(self, identity):
        return {key: value for key, value in self.user.items() if key != "password"}


def make_client():
    app = create_app({
        "TESTING": True,
        "PIPELINE_ENABLED": False,
        "JWT_SECRET": "integration-secret",
        "MONGO_URI": "mongodb://127.0.0.1:1/test?serverSelectionTimeoutMS=50",
    })
    app.extensions["sanxia_services"]["users"] = FakeUsers()
    return app.test_client()


def test_login_and_me_contract():
    client = make_client()
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret"})
    assert login.status_code == 200
    token = login.get_json()["data"]["accessToken"]
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.get_json()["data"]["username"] == "admin"


def test_protected_endpoint_requires_bearer_token():
    client = make_client()
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "AUTH_REQUIRED"


def test_dashboard_realtime_endpoint_contract():
    class FakeDashboard:
        @staticmethod
        def realtime(interval, end, points, pipeline, events):
            assert interval == 2000
            assert end is None
            assert points == 6
            assert pipeline.status()["runId"] == "run-api"
            assert events.total() == 7
            return {
                "summary": {"pie_data": [{"name": "Normal", "total": 3}], "list_data": [], "percentage_data": {}},
                "history": [],
                "totals": {"monitoredTraffic": 3, "attackAlerts": 0, "riskEvents": 7},
                "pipeline": pipeline.status(),
                "generatedAt": "2026-10-03T00:00:00+00:00",
            }

    class FakePipeline:
        @staticmethod
        def status():
            return {"runId": "run-api", "running": False}

    class FakeEventTotals:
        @staticmethod
        def total():
            return 7

    client = make_client()
    services = client.application.extensions["sanxia_services"]
    services["dashboard"] = FakeDashboard()
    services["pipeline"] = FakePipeline()
    services["events"] = FakeEventTotals()
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret"})
    token = login.get_json()["data"]["accessToken"]

    response = client.get(
        "/api/v1/dashboard/realtime?intervalMs=2000&points=6",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["totals"]["riskEvents"] == 7
    assert data["pipeline"]["runId"] == "run-api"



class FakeEvents:
    def judgements(self, limit, association_service):
        return {"items": [{"eventId": "event-1", "limit": limit}], "limit": limit}

    def detail(self, event_id, association_service):
        from app.errors import ApiError
        if event_id == "invalid":
            raise ApiError("INVALID_EVENT_ID", "事件 ID 格式无效", 400)
        if event_id == "507f1f77bcf86cd799439099":
            raise ApiError("EVENT_NOT_FOUND", "未找到对应的告警事件", 404)
        return {"event": {"_id": event_id}, "judgement": {"eventId": event_id}}

    def update_disposition(self, event_id, actor, data, association_service):
        return {"event": {"_id": event_id, "disposition": {**data, "updatedBy": actor["username"]}}, "judgement": {"eventId": event_id}}


class FakeModbus:
    pass


def test_judgements_endpoint_returns_latest_five_contract():
    client = make_client()
    client.application.extensions["sanxia_services"]["events"] = FakeEvents()
    client.application.extensions["sanxia_services"]["modbus"] = FakeModbus()
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret"})
    token = login.get_json()["data"]["accessToken"]

    response = client.get("/api/v1/events/judgements?limit=5", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.get_json()["data"]["items"] == [{"eventId": "event-1", "limit": 5}]


def _event_client():
    client = make_client()
    client.application.extensions["sanxia_services"]["events"] = FakeEvents()
    client.application.extensions["sanxia_services"]["modbus"] = FakeModbus()
    login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret"})
    return client, login.get_json()["data"]["accessToken"]


def test_event_detail_contract():
    client, token = _event_client()

    response = client.get("/api/v1/events/507f1f77bcf86cd799439011", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.get_json()["data"]["event"]["_id"] == "507f1f77bcf86cd799439011"
    assert response.get_json()["data"]["judgement"]["eventId"] == "507f1f77bcf86cd799439011"


def test_event_disposition_contract():
    client, token = _event_client()
    response = client.patch(
        "/api/v1/events/507f1f77bcf86cd799439011/disposition",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "investigating", "assignee": "admin", "confirmedAttackType": "未知异常", "actualImpact": "暂无实际影响", "conclusion": "正在核验", "note": "检查通信记录"},
    )
    assert response.status_code == 200
    assert response.get_json()["data"]["event"]["disposition"]["status"] == "investigating"
    assert response.get_json()["data"]["event"]["disposition"]["confirmedAttackType"] == "未知异常"
    assert response.get_json()["data"]["event"]["disposition"]["actualImpact"] == "暂无实际影响"
    assert response.get_json()["data"]["event"]["disposition"]["updatedBy"] == "admin"


@pytest.mark.parametrize(
    ("event_id", "status", "code"),
    [
        ("invalid", 400, "INVALID_EVENT_ID"),
        ("507f1f77bcf86cd799439099", 404, "EVENT_NOT_FOUND"),
    ],
)
def test_event_detail_error_contract(event_id, status, code):
    client, token = _event_client()

    response = client.get(f"/api/v1/events/{event_id}", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == status
    assert response.get_json()["error"]["code"] == code
