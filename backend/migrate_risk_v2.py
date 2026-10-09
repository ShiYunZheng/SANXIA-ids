from collections import Counter

from pymongo import MongoClient

from app.config import Config
from app.repositories.mongo import EventRepository
from app.risk import RiskPolicy


def summarize(events):
    return dict(Counter(
        (
            event.get("severityPolicyVersion") or "none",
            event.get("severitySource") or "none",
            event.get("eventSeverity"),
        )
        for event in events
    ))


def main():
    client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
    collection = client.get_default_database().event
    repository = EventRepository(collection)
    policy = RiskPolicy(
        Config.RISK_DURATION_SECONDS,
        Config.RISK_SAMPLE_THRESHOLD,
        Config.RISK_TARGET_THRESHOLD,
        Config.RISK_CONFIDENCE_THRESHOLD,
    )

    before = [event for event in collection.find({}) if event.get("engine") != "standalone"]
    print("BEFORE", len(before), summarize(before))
    modified = repository.normalize_risk_assessments(policy)
    second_pass = repository.normalize_risk_assessments(policy)
    after = [event for event in collection.find({}) if event.get("engine") != "standalone"]
    labels = Counter(
        (
            event.get("attackLabel") or "none",
            event.get("eventSeverity"),
            event.get("severityStatus") or "none",
        )
        for event in after
    )
    print("MODIFIED", modified)
    print("IDEMPOTENT_SECOND", second_pass)
    print("AFTER", len(after), summarize(after))
    print("LABELS", dict(labels))


if __name__ == "__main__":
    main()
