from app.constants import ATTACK_TYPES, MACHINE_COMPONENTS
from app.services.analytics import DashboardService


class RealtimeRepository:
    def summary_counts(self):
        return [
            {"_id": {"attack_type": "Normal", "machine_component": MACHINE_COMPONENTS[0]}, "count": 100},
            {"_id": {"attack_type": "Modbus模糊测试", "machine_component": MACHINE_COMPONENTS[1]}, "count": 10},
        ]

    def history(self, _start, _end, _bucket, _attack_types):
        return [{"_id": {"bucket": 1, "attack_type": "Modbus模糊测试"}, "count": 4}]

    @staticmethod
    def latest_timestamp():
        return None


class RealtimePipeline:
    @staticmethod
    def status():
        return {
            "runId": "run-live",
            "runStatus": "running",
            "running": True,
            "processedSamples": 20,
            "insertedSamples": 5,
            "attackSamples": 8,
            "attackPredictions": 8,
            "candidateAlerts": 4,
            "eventsCreated": 2,
            "labelDistribution": {"Normal": 12, "Modbus模糊测试": 8},
            "persistedLabelDistribution": {"Normal": 3, "Modbus模糊测试": 2},
            "shadowMode": False,
            "lastError": None,
        }


class RealtimeEvents:
    @staticmethod
    def total():
        return 10


def test_realtime_dashboard_merges_only_unpersisted_run_delta():
    service = DashboardService(RealtimeRepository())

    snapshot = service.realtime(60_000, 120_000, 2, RealtimePipeline(), RealtimeEvents())

    by_label = {item["name"]: item["total"] for item in snapshot["summary"]["pie_data"]}
    assert by_label["Normal"] == 109
    assert by_label["Modbus模糊测试"] == 16
    assert snapshot["totals"] == {
        "monitoredTraffic": 125,
        "attackAlerts": 16,
        "riskEvents": 12,
    }
    assert snapshot["history"][-1]["Modbus模糊测试"] == 10
    assert snapshot["pipeline"]["runId"] == "run-live"
    assert snapshot["pipeline"]["persistedLabelDistribution"] == {
        "Normal": 3,
        "Modbus模糊测试": 2,
    }


def test_summary_uses_one_aggregation_and_keeps_all_known_labels():
    summary = DashboardService(RealtimeRepository()).summary()

    assert [item["name"] for item in summary["pie_data"]] == ATTACK_TYPES
    assert sum(item["total"] for item in summary["pie_data"]) == 110
