from .attack import blueprint as attack_blueprint
from .auth import blueprint as auth_blueprint
from .dashboard import blueprint as dashboard_blueprint
from .detections import blueprint as detections_blueprint
from .events import blueprint as events_blueprint
from .health import blueprint as health_blueprint
from .pipeline import blueprint as pipeline_blueprint
from .records import blueprint as records_blueprint
from .sampling import blueprint as sampling_blueprint
from .users import blueprint as users_blueprint
from .validation import blueprint as validation_blueprint


BLUEPRINTS = [
    health_blueprint,
    pipeline_blueprint,
    auth_blueprint,
    users_blueprint,
    dashboard_blueprint,
    records_blueprint,
    events_blueprint,
    detections_blueprint,
    sampling_blueprint,
    attack_blueprint,
    validation_blueprint,
]
