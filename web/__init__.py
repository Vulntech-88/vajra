# web/__init__.py
from flask import Flask
from datetime import datetime

def create_app():
    app = Flask(__name__)
    app.secret_key = 'super-secure-key'

    # Register custom filters
    @app.template_filter('datetime')
    def format_datetime(value):
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
        return value

    from web.routes.dashboard_routes import dashboard_bp
    from web.routes.scan_routes import scan_bp

    app.register_blueprint(scan_bp)
    app.register_blueprint(dashboard_bp)

    return app






