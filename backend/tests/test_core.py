import json

from bson import ObjectId
from flask import Flask

from app.api_response import success
from app.auth import create_access_token, decode_access_token
from app.services.analytics import EventQueue
from app.services.sampling import SampleBuffer


def test_success_response_serializes_object_id():
    app = Flask(__name__)
    with app.app_context():
        identifier = ObjectId()
        response = success({"id": identifier})
    assert response.status_code == 200
    assert json.loads(response.get_data(as_text=True)) == {"data": {"id": str(identifier)}}


def test_access_token_round_trip():
    app = Flask(__name__)
    app.config.update(JWT_SECRET="test-secret", JWT_EXPIRES_MINUTES=5)
    user = {"_id": ObjectId(), "username": "admin", "role": 0}
    with app.app_context():
        payload = decode_access_token(create_access_token(user))
    assert payload["sub"] == str(user["_id"])
    assert payload["username"] == "admin"


def test_event_queue_returns_highest_priority_first():
    events = EventQueue()
    events.push({"eventSeverity": 3, "name": "low"})
    events.push({"eventSeverity": 0, "name": "critical"})
    assert events.pop()["name"] == "critical"


def test_sample_buffer_drains_and_honors_limit():
    samples = SampleBuffer(max_size=2)
    samples.add({"id": 1})
    samples.add({"id": 2})
    samples.add({"id": 3})
    assert samples.drain() == [{"id": 2}, {"id": 3}]
    assert samples.drain() == []

