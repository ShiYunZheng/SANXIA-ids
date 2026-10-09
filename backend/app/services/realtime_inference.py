import uuid
from collections import deque
from datetime import datetime, timezone

from bson import ObjectId

from .analytics import EventBroadcaster


class RealtimeInferenceService:
    """Persist and broadcast in-process Modbus sliding-window results."""

    def __init__(self, repository, events, engine):
        self.repository = repository
        self.events = events
        self.engine = engine
        self.broadcaster = EventBroadcaster()
        self._volatile = deque(maxlen=500)
        self._volatile_active = False

    def begin_run(self, shadow=False):
        self._volatile.clear()
        self._volatile_active = bool(shadow)

    def persist(self, inference):
        return self.process(inference, persist=True)

    def process(self, inference, persist=True):
        created = []
        engine_name = inference.get("engine", "modbus-fast")
        for window in inference.get("windows", []):
            label = window.get("predictedLabel") or "unknown"
            association = self.engine.associate(window) if label != "normal" else {}
            severity = (association.get("attackInfo") or {}).get("severity") if association else "normal"
            document = {
                **window,
                "engine": engine_name,
                "severity": severity or "unknown",
                "association": association,
                "createdAt": datetime.now(timezone.utc),
            }
            if persist:
                inserted = self.repository.insert_if_new(document)
                if inserted is None:
                    continue
            else:
                inserted = {**document, "_id": f"shadow-{uuid.uuid4().hex}"}
            serialized = self.serialize(inserted)
            created.append(serialized)
            if not persist:
                self._volatile.appendleft(serialized)
            self.broadcaster.publish(serialized)
        return created

    def latest(self, limit=5):
        if self._volatile_active:
            return {"items": list(self._volatile)[:limit], "limit": limit, "shadowMode": True}
        return {"items": [self.serialize(item) for item in self.repository.latest(limit)], "limit": limit}

    def subscribe(self):
        return self.broadcaster.subscribe()

    def unsubscribe(self, subscriber):
        self.broadcaster.unsubscribe(subscriber)

    @staticmethod
    def serialize(document):
        current = dict(document)
        if isinstance(current.get("_id"), ObjectId):
            current["_id"] = str(current["_id"])
        if isinstance(current.get("createdAt"), datetime):
            current["createdAt"] = current["createdAt"].astimezone(timezone.utc).isoformat()
        return current
