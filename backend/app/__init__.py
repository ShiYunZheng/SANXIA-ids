import atexit
import logging
from pathlib import Path

from flask import Flask
from flask_cors import CORS
from flask_pymongo import PyMongo
from pymongo.errors import PyMongoError

from .api import BLUEPRINTS
from .cascade import CascadeDetectionModel
from .config import Config
from .errors import register_error_handlers
from .modbus import ModbusInferenceEngine
from .repositories import DashboardRepository, EventRepository, JudgementRepository, RealtimeInferenceRepository, RecordRepository, UserRepository
from .risk import RiskPolicy
from .services import AttackService, DashboardService, DetectionService, EventService, PipelineWorker, RealtimeInferenceService, RecordService, SamplingService, UserService, ValidationService


def create_app(config_overrides=None):
    Config.validate()
    app = Flask(__name__)
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["PIPELINE_PCAP_DIR"]).mkdir(parents=True, exist_ok=True)
    CORS(app, resources={r"/api/*": {"origins": "*"}}, allow_headers=["Authorization", "Content-Type"])
    register_error_handlers(app)

    mongo = PyMongo(
        app,
        connect=False,
        connectTimeoutMS=app.config["MONGO_CONNECT_TIMEOUT_MS"],
        serverSelectionTimeoutMS=app.config["MONGO_CONNECT_TIMEOUT_MS"],
    )
    database = mongo.db
    user_repository = UserRepository(database.users)
    dashboard_repository = DashboardRepository(database.dashboard, database.dashboard_batches)
    record_repository = RecordRepository(database.record)
    event_repository = EventRepository(database.event)
    judgement_repository = JudgementRepository(database.judgements)
    realtime_inference_repository = RealtimeInferenceRepository(database.realtime_inference_results)

    cascade_model = CascadeDetectionModel(
        app.config["KNOWN_ATTACK_MODEL_PATH"], app.config["UNKNOWN_ATTACK_MODEL_PATH"],
        app.config["UNKNOWN_ATTACK_METADATA_PATH"], app.config["MODEL_DEVICE"], app.config["MODEL_BATCH_SIZE"],
    )
    try:
        cascade_model.load()
    except Exception as error:
        logging.getLogger(__name__).warning("Cascade model startup validation failed: %s", error)

    users = UserService(user_repository)
    dashboard = DashboardService(dashboard_repository)
    records = RecordService(record_repository)
    risk_policy = RiskPolicy(
        app.config["RISK_DURATION_SECONDS"], app.config["RISK_SAMPLE_THRESHOLD"],
        app.config["RISK_TARGET_THRESHOLD"], app.config["RISK_CONFIDENCE_THRESHOLD"],
    )
    events = EventService(event_repository, risk_policy)
    detection = DetectionService(cascade_model, app.config["UPLOAD_DIR"], app.config["SAMPLE_MACHINE_NAME"])
    sampling = SamplingService(
        app.config["SAMPLE_SOURCE"], app.config["INPUT_PCAP_PATH"], app.config["INPUT_TRAFFIC_PATH"],
        app.config["SAMPLE_MACHINE_NAME"], app.config["SAMPLE_IP_ADDRESS"], app.config["SAMPLE_INTERFACE"],
        app.config["PIPELINE_PCAP_DIR"], app.config["MAX_CONTENT_LENGTH"], app.config["PIPELINE_REPLAY_INTERVAL_SECONDS"],
    )
    attack = AttackService(app.config["INPUT_TRAFFIC_PATH"])
    modbus = ModbusInferenceEngine(app.config["MODBUS_RESOURCE_DIR"])
    events.association_service = modbus
    realtime_inference = RealtimeInferenceService(realtime_inference_repository, events, modbus)
    pipeline = PipelineWorker(
        sampling, detection, dashboard, records, events, app.config["PIPELINE_INTERVAL_SECONDS"],
        modbus=modbus, realtime_inference=realtime_inference,
    )
    validation = ValidationService(detection, modbus, app.config["UPLOAD_DIR"], judgement_repository)

    app.extensions["sanxia_services"] = {
        "mongo": mongo, "cascade_model": cascade_model, "users": users, "dashboard": dashboard,
        "records": records, "events": events, "detection": detection, "modbus": modbus, "sampling": sampling,
        "attack": attack, "pipeline": pipeline, "validation": validation, "realtime_inference": realtime_inference,
    }

    for blueprint in BLUEPRINTS:
        prefix = f'{app.config["API_PREFIX"]}{blueprint.url_prefix or ""}'
        app.register_blueprint(blueprint, url_prefix=prefix)

    try:
        user_repository.ensure_indexes()
        dashboard_repository.ensure_indexes()
        event_repository.ensure_indexes()
        corrected_events = event_repository.normalize_risk_assessments(risk_policy)
        if corrected_events:
            app.logger.info("Normalized severity for %s SANXIA events", corrected_events)
        judgement_repository.ensure_indexes()
        realtime_inference_repository.ensure_indexes()
    except PyMongoError as error:
        app.logger.warning("Database indexes will be retried after MongoDB becomes available: %s", error)

    if app.config["PIPELINE_ENABLED"]:
        try:
            pipeline.start()
        except Exception as error:
            app.logger.warning("Pipeline is configured but could not start: %s", error)

    atexit.register(pipeline.stop)
    return app


