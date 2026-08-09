"""
config.py

Central configuration for the Flask backend.
"""

import os


# Backend folder
BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

# Main project folder
PROJECT_ROOT = os.path.abspath(
    os.path.join(
        BASE_DIR,
        ".."
    )
)


class Config:
    """Base configuration."""

    DEBUG = False

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    DATABASE_PATH = os.path.join(
        PROJECT_ROOT,
        "database",
        "scanner.db"
    )

    # --------------------------------------------------------
    # Decision Tree model
    # --------------------------------------------------------

    # Generated automatically by:
    #
    # python model/train_model.py

    MODEL_PATH = os.path.join(
        BASE_DIR,
        "model",
        "decision_tree_model.joblib"
    )

    MODEL_COLUMNS_PATH = os.path.join(
        BASE_DIR,
        "model",
        "feature_columns.json"
    )

    # --------------------------------------------------------
    # Reports
    # --------------------------------------------------------

    REPORTS_DIR = os.path.join(
        PROJECT_ROOT,
        "reports"
    )

    # --------------------------------------------------------
    # Dashboard
    # --------------------------------------------------------

    DASHBOARD_DIR = os.path.join(
        PROJECT_ROOT,
        "dashboard"
    )

    # --------------------------------------------------------
    # CORS
    # --------------------------------------------------------

    CORS_ORIGINS = "*"

    # --------------------------------------------------------
    # Flask server
    # --------------------------------------------------------

    # Keep the development backend local.
    HOST = "127.0.0.1"

    PORT = 5000


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}


def get_config(
    env_name="development"
):
    """
    Return the requested Flask configuration.
    """

    name = str(
        env_name
    ).strip().lower()

    return CONFIG_MAP.get(
        name,
        DevelopmentConfig
    )