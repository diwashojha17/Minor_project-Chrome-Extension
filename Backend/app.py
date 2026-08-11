"""
app.py

Main Flask application entry point.

Connects:
- Flask API
- SQLite database
- Decision Tree predictor
- Dashboard routes

Run from the Backend directory:

    python app.py
"""

import os

from flask import Flask


# ------------------------------------------------------------
# Optional Flask-CORS support
# ------------------------------------------------------------

try:
    from flask_cors import CORS

    HAS_FLASK_CORS = True

except ImportError:
    HAS_FLASK_CORS = False


# ------------------------------------------------------------
# Local imports
# ------------------------------------------------------------

from config import get_config

import database

from predictor import VulnerabilityPredictor

from routes import (
    api_bp,
    dashboard_bp,
)


# ============================================================
# Application factory
# ============================================================

def create_app(
    env_name="development"
):

    app = Flask(
        __name__
    )

    # --------------------------------------------------------
    # Configuration
    # --------------------------------------------------------

    config = get_config(
        env_name
    )

    app.config[
        "APP_CONFIG"
    ] = config


    # --------------------------------------------------------
    # CORS
    # --------------------------------------------------------

    # Chrome extensions use a chrome-extension:// origin.
    # During development the local backend accepts API
    # requests from the extension.

    if HAS_FLASK_CORS:

        CORS(
            app,
            resources={
                r"/api/*": {
                    "origins": "*"
                }
            }
        )

    else:

        @app.after_request
        def add_cors_headers(response):

            response.headers[
                "Access-Control-Allow-Origin"
            ] = "*"

            response.headers[
                "Access-Control-Allow-Headers"
            ] = "Content-Type"

            response.headers[
                "Access-Control-Allow-Methods"
            ] = "GET, POST, OPTIONS"

            return response


    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    database.init_db(
        config
    )


    # --------------------------------------------------------
    # Decision Tree predictor
    # --------------------------------------------------------

    # The updated VulnerabilityPredictor does NOT crash
    # when the model hasn't been trained yet.
    #
    # /api/health will return:
    #
    # modelReady: false
    #
    # until train_model.py creates the .joblib model.

    predictor = VulnerabilityPredictor(
        model_path=
            config.MODEL_PATH,

        columns_path=
            config.MODEL_COLUMNS_PATH
    )

    app.config[
        "PREDICTOR"
    ] = predictor


    # --------------------------------------------------------
    # Routes
    # --------------------------------------------------------

    app.register_blueprint(
        api_bp
    )

    app.register_blueprint(
        dashboard_bp
    )


    # --------------------------------------------------------
    # Startup information
    # --------------------------------------------------------

    if predictor.is_ready():

        app.logger.info(
            "Decision Tree model loaded."
        )

    else:

        app.logger.warning(
            "Decision Tree model is not trained yet."
        )


    return app


# ============================================================
# Run directly
# ============================================================

if __name__ == "__main__":

    environment = os.environ.get(
        "FLASK_ENV",
        "development"
    )

    application = create_app(
        environment
    )

    config = application.config[
        "APP_CONFIG"
    ]

    print()
    print(
        "AI Web Vulnerability Scanner"
    )

    print(
        f"Backend: "
        f"http://{config.HOST}:{config.PORT}"
    )

    print(
        f"Health: "
        f"http://{config.HOST}:{config.PORT}/api/health"
    )

    print(
        f"Dashboard: "
        f"http://{config.HOST}:{config.PORT}/dashboard"
    )

    predictor = application.config[
        "PREDICTOR"
    ]

    print(
        "Decision Tree: "
        + (
            "READY"
            if predictor.is_ready()
            else "NOT TRAINED"
        )
    )

    print()

    application.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )