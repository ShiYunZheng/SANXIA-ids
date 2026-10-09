from test_api import make_client
from io import BytesIO

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


def _authorized_client():
    client = make_client()
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret"})
    token = response.get_json()["data"]["accessToken"]
    return client, {"Authorization": f"Bearer {token}"}


def test_pipeline_can_start_and_stop_with_bundled_csv():
    client, headers = _authorized_client()
    started = client.post("/api/v1/pipeline/start", headers=headers)
    assert started.status_code == 200
    data = started.get_json()["data"]
    assert data["running"] is True
    assert data["sampling"]["source"] == "csv"
    assert data["insertedSamples"] == 0
    assert data["duplicateSamples"] == 0
    assert data["sourceFingerprint"] == data["sampling"]["sourceFingerprint"]

    stopped = client.post("/api/v1/pipeline/stop", headers=headers)
    assert stopped.status_code == 200
    assert stopped.get_json()["data"]["running"] is False


def test_pipeline_start_accepts_shadow_mode():
    client, headers = _authorized_client()
    started = client.post("/api/v1/pipeline/start", headers=headers, json={"persist": False})
    assert started.status_code == 200
    data = started.get_json()["data"]
    assert data["shadowMode"] is True
    assert data["persistenceMode"] == "shadow"
    client.post("/api/v1/pipeline/stop", headers=headers)


def test_pipeline_start_rejects_non_boolean_persist():
    client, headers = _authorized_client()
    response = client.post("/api/v1/pipeline/start", headers=headers, json={"persist": "false"})
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_PERSIST_MODE"


def test_unavailable_source_does_not_replace_current_source():
    client, headers = _authorized_client()
    response = client.post("/api/v1/pipeline/source", headers=headers, json={"source": "pcap"})
    assert response.status_code == 503
    status = client.get("/api/v1/pipeline", headers=headers)
    assert status.get_json()["data"]["sampling"]["source"] == "csv"


def test_sources_endpoint_reports_all_source_types():
    client, headers = _authorized_client()
    response = client.get("/api/v1/pipeline/sources", headers=headers)
    assert response.status_code == 200, response.get_json()
    data = response.get_json()["data"]
    assert [item["source"] for item in data["sources"]] == ["csv", "pcap", "replay", "interface"]
    assert data["sources"][0]["available"] is True
    assert data["sources"][2]["simulated"] is True


def test_runtime_alert_query_requires_auth_and_returns_items():
    client, headers = _authorized_client()
    unauthorized = client.get("/api/v1/pipeline/alerts")
    assert unauthorized.status_code == 401

    pipeline = client.application.extensions["sanxia_services"]["pipeline"]
    pipeline._alert_feed.publish({"alertId": "alert-1", "runId": "run-1", "archiveStatus": "deduplicated"})
    response = client.get("/api/v1/pipeline/alerts?runId=run-1&limit=10", headers=headers)

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["runId"] == "run-1"
    assert data["total"] == 1
    assert data["returned"] == 1
    assert data["items"][0]["alertId"] == "alert-1"


def test_runtime_alert_total_is_not_reduced_by_limit():
    client, headers = _authorized_client()
    pipeline = client.application.extensions["sanxia_services"]["pipeline"]
    pipeline._run_id = "run-limited"
    pipeline._runtime_alerts = 5
    for index in range(3):
        pipeline._alert_feed.publish({"alertId": f"alert-{index}", "runId": "run-limited"})

    response = client.get("/api/v1/pipeline/alerts?runId=run-limited&limit=2", headers=headers)

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["total"] == 5
    assert data["returned"] == 2
    assert len(data["items"]) == 2


def test_valid_pcap_upload_is_saved_and_selected(tmp_path):
    client, headers = _authorized_client()
    sampling = client.application.extensions["sanxia_services"]["sampling"]
    sampling.upload_dir = tmp_path / "pipeline_sources"
    pipeline = client.application.extensions["sanxia_services"]["pipeline"]
    previous_context = pipeline.status()["sourceContextId"]
    pipeline._run_id = "previous-run"
    pipeline._processed_samples = 17
    pipeline._runtime_alerts = 3
    source = tmp_path / "sample.pcap"
    wrpcap(str(source), [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / Raw(b"hello")])

    response = client.post(
        "/api/v1/pipeline/pcap", headers=headers,
        data={"file": (BytesIO(source.read_bytes()), "capture.pcap")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["sampling"]["source"] == "pcap"
    assert data["sampling"]["sourceFileName"] == "capture.pcap"
    assert data["upload"]["fingerprint"] in sampling.pcap_path.name
    assert data["sourceContextId"] != previous_context
    assert data["runId"] is None
    assert data["runStatus"] == "idle"
    assert data["processedSamples"] == 0
    assert data["runtimeAlerts"] == 0


def test_replay_pcap_upload_is_marked_as_simulated_source(tmp_path):
    client, headers = _authorized_client()
    sampling = client.application.extensions["sanxia_services"]["sampling"]
    sampling.upload_dir = tmp_path / "pipeline_sources"
    source = tmp_path / "sample-replay.pcap"
    wrpcap(str(source), [IP(src="10.10.0.1", dst="10.10.0.2") / TCP(sport=1234, dport=502) / Raw(b"replay")])

    response = client.post(
        "/api/v1/pipeline/pcap", headers=headers,
        data={"source": "replay", "file": (BytesIO(source.read_bytes()), "capture-replay.pcap")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200, response.get_json()
    data = response.get_json()["data"]
    assert data["sampling"]["source"] == "replay"
    assert data["sampling"]["simulated"] is True
    assert data["sampling"]["sourceFileName"] == "capture-replay.pcap"


def test_invalid_pcap_upload_is_rejected_without_switching(tmp_path):
    client, headers = _authorized_client()
    sampling = client.application.extensions["sanxia_services"]["sampling"]
    pipeline = client.application.extensions["sanxia_services"]["pipeline"]
    previous_context = pipeline.status()["sourceContextId"]
    sampling.upload_dir = tmp_path
    response = client.post(
        "/api/v1/pipeline/pcap", headers=headers,
        data={"file": (BytesIO(b"not a capture"), "broken.pcap")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert sampling.source == "csv"
    assert pipeline.status()["sourceContextId"] == previous_context


def test_interface_selection_requires_enumerated_available_device():
    client, headers = _authorized_client()
    sampling = client.application.extensions["sanxia_services"]["sampling"]
    device_id = r"\Device\NPF_{TEST-GUID}"
    sampling.interface_catalog = lambda: [{
        "name": "WLAN", "description": "Test Wi-Fi", "deviceId": device_id,
        "ip": "10.0.0.2", "available": True, "recommended": True, "reason": None,
    }]
    response = client.post(
        "/api/v1/pipeline/source", headers=headers,
        json={"source": "interface", "interface": device_id, "machineName": "以太网交换机"},
    )
    assert response.status_code == 200
    assert response.get_json()["data"]["sampling"]["interfaceName"] == "WLAN"
    assert response.get_json()["data"]["sampling"]["machineName"] == "以太网交换机"


def test_interface_selection_rejects_unknown_machine_component():
    client, headers = _authorized_client()
    sampling = client.application.extensions["sanxia_services"]["sampling"]
    device_id = r"\Device\NPF_{TEST-GUID}"
    sampling.interface_catalog = lambda: [{
        "name": "WLAN", "description": "Test Wi-Fi", "deviceId": device_id,
        "ip": "10.0.0.2", "available": True, "recommended": True, "reason": None,
    }]
    response = client.post(
        "/api/v1/pipeline/source", headers=headers,
        json={"source": "interface", "interface": device_id, "machineName": "test"},
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "INVALID_MACHINE_COMPONENT"
