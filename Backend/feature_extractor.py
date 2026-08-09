"""
feature_extractor.py

Validates and normalizes security features received from the
Chrome extension before sending them to the Decision Tree model.

IMPORTANT:
- FEATURE_ORDER must match Extension/featureExtractor.js.
- Surface features such as login_surface describe page structure.
- login_surface does NOT mean brute-force vulnerability.
"""

from typing import Dict, Any, List
import math


# Exact feature order expected by the future Decision Tree model.
FEATURE_ORDER: List[str] = [
    # Transport / headers
    "https",
    "csp",
    "hsts",
    "x_frame_options",
    "x_content_type_options",

    # Cookies
    "secure_cookie",
    "httponly_cookie",
    "samesite_cookie",

    # Page structure
    "num_forms",
    "password_fields",
    "url_length",
    "query_parameters",
    "external_scripts",
    "inline_scripts",

    # HTTP
    "http_status",

    # Active vulnerability indicators
    "sql_error_indicator",
    "reflected_payload_indicator",
    "server_error_indicator",
    "mixed_content_count",
    "exposed_paths",
    "blind_sqli_indicator",

    # Passive vulnerability indicators
    "dom_xss_indicator",
    "csrf_missing_token",
    "unsafe_upload_indicator",
    "weak_session_indicator",
    "weak_csp_indicator",

    # Active redirect indicator
    "open_redirect_indicator",

    # Informational attack-surface features
    "command_input_surface",
    "file_path_input_surface",
    "stored_input_surface",
    "file_upload_surface",
    "login_surface",
    "api_surface",
]


DEFAULTS: Dict[str, Any] = {
    "https": 0,
    "csp": 0,
    "hsts": 0,
    "x_frame_options": 0,
    "x_content_type_options": 0,

    "secure_cookie": 0,
    "httponly_cookie": 0,
    "samesite_cookie": 0,

    "num_forms": 0,
    "password_fields": 0,
    "url_length": 0,
    "query_parameters": 0,
    "external_scripts": 0,
    "inline_scripts": 0,

    "http_status": 200,

    "sql_error_indicator": 0,
    "reflected_payload_indicator": 0,
    "server_error_indicator": 0,
    "mixed_content_count": 0,
    "exposed_paths": 0,
    "blind_sqli_indicator": 0,

    "dom_xss_indicator": 0,
    "csrf_missing_token": 0,
    "unsafe_upload_indicator": 0,
    "weak_session_indicator": 0,
    "weak_csp_indicator": 0,

    "open_redirect_indicator": 0,

    "command_input_surface": 0,
    "file_path_input_surface": 0,
    "stored_input_surface": 0,
    "file_upload_surface": 0,
    "login_surface": 0,
    "api_surface": 0,
}


BINARY_FEATURES = {
    "https",
    "csp",
    "hsts",
    "x_frame_options",
    "x_content_type_options",
    "secure_cookie",
    "httponly_cookie",
    "samesite_cookie",

    "sql_error_indicator",
    "reflected_payload_indicator",
    "server_error_indicator",
    "blind_sqli_indicator",

    "dom_xss_indicator",
    "csrf_missing_token",
    "unsafe_upload_indicator",
    "weak_session_indicator",
    "weak_csp_indicator",
    "open_redirect_indicator",

    "command_input_surface",
    "file_path_input_surface",
    "stored_input_surface",
    "file_upload_surface",
    "login_surface",
    "api_surface",
}


NON_NEGATIVE_FEATURES = {
    "num_forms",
    "password_fields",
    "url_length",
    "query_parameters",
    "external_scripts",
    "inline_scripts",
    "mixed_content_count",
    "exposed_paths",
}


def _to_number(value: Any, default: float) -> float:
    """Safely convert an incoming value to a finite float."""
    try:
        number = float(value)

        if not math.isfinite(number):
            return float(default)

        return number

    except (TypeError, ValueError):
        return float(default)


def normalize_features(raw_features: Dict[str, Any]) -> Dict[str, float]:
    """
    Validate and normalize the feature dictionary received
    from the Chrome extension.
    """

    if not isinstance(raw_features, dict):
        raw_features = {}

    normalized: Dict[str, float] = {}

    for key in FEATURE_ORDER:
        default = DEFAULTS[key]

        value = _to_number(
            raw_features.get(key, default),
            default
        )

        # Binary features must always become 0 or 1.
        if key in BINARY_FEATURES:
            value = 1.0 if value >= 0.5 else 0.0

        # Counts cannot be negative.
        elif key in NON_NEGATIVE_FEATURES:
            value = max(0.0, value)

        # HTTP status should remain sensible.
        elif key == "http_status":
            if value < 100 or value > 599:
                value = 200.0

        normalized[key] = value

    return normalized


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """
    Convert feature dictionary into the exact ordered vector
    required by model.predict().
    """

    normalized = normalize_features(features)

    return [
        normalized[key]
        for key in FEATURE_ORDER
    ]


def get_feature_names() -> List[str]:
    """Return the model feature names in their required order."""
    return FEATURE_ORDER.copy()


def get_feature_count() -> int:
    """Return total number of ML input features."""
    return len(FEATURE_ORDER)