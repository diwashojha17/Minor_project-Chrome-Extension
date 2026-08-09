"""
routes.py

Flask API routes used by the Chrome extension and dashboard.
"""

import os
import time
import uuid

from urllib.parse import (
    urlparse,
    parse_qsl,
)

from flask import (
    Blueprint,
    request,
    jsonify,
    send_from_directory,
    send_file,
    current_app,
    redirect,
)

import database
import scanner as server_scanner

from feature_extractor import (
    FEATURE_ORDER,
    normalize_features,
)

from analyzer import (
    build_recommendations,
    summarize_prediction,
)

from report_generator import (
    generate_pdf_report,
    generate_csv_report,
    generate_history_csv,
)

from utils import (
    sanitize_filename,
    ensure_dir,
    is_valid_url,
)


api_bp = Blueprint(
    "api",
    __name__,
    url_prefix="/api"
)

dashboard_bp = Blueprint(
    "dashboard",
    __name__
)


# ============================================================
# Helpers
# ============================================================

def is_local_training_lab(url: str) -> bool:
    """
    Active server-side scanning is restricted to
    the user's local training environment.
    """

    try:
        hostname = (
            urlparse(url)
            .hostname
        )

        return hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }

    except Exception:
        return False


def safe_integer(
    value,
    default,
    minimum,
    maximum
):
    """Safely parse bounded integer query parameters."""

    try:
        number = int(value)

    except (TypeError, ValueError):
        return default

    return max(
        minimum,
        min(maximum, number)
    )


# ============================================================
# Health
# ============================================================

@api_bp.route(
    "/health",
    methods=["GET"]
)
def health():

    predictor = current_app.config.get(
        "PREDICTOR"
    )

    model_ready = bool(
        predictor
        and predictor.is_ready()
    )

    return jsonify({
        "status": "ok",
        "time": int(time.time()),
        "modelReady": model_ready,
        "featureCount": len(FEATURE_ORDER),
    })


# ============================================================
# Decision Tree prediction
# ============================================================

@api_bp.route(
    "/scan/predict",
    methods=["POST"]
)
def predict():

    payload = request.get_json(
        force=True,
        silent=True
    ) or {}

    raw_features = payload.get(
        "features"
    )

    if not isinstance(
        raw_features,
        dict
    ):
        return jsonify({
            "error":
                "features must be a JSON object."
        }), 400

    predictor = current_app.config[
        "PREDICTOR"
    ]

    if not predictor.is_ready():
        return jsonify({
            "error":
                "Decision Tree model has not been trained yet.",

            "modelReady": False,

            "featureCount":
                len(FEATURE_ORDER)
        }), 503

    try:
        normalized = normalize_features(
            raw_features
        )

        result = predictor.predict(
            normalized
        )

        return jsonify({
            "label":
                result["label"],

            "confidence":
                result["confidence"],

            "probabilities":
                result["probabilities"],

            "score":
                result["risk_score"],

            "risk_score":
                result["risk_score"],

            "security_score":
                result["security_score"],

            "modelReady": True,
        })

    except Exception as error:

        current_app.logger.exception(
            "Prediction failed"
        )

        return jsonify({
            "error":
                "Prediction failed.",

            "details":
                str(error)
        }), 500


# ============================================================
# Save completed extension scan
# ============================================================

@api_bp.route(
    "/scan/save",
    methods=["POST"]
)
def save_scan():

    payload = request.get_json(
        force=True,
        silent=True
    ) or {}

    url = str(
        payload.get("url", "")
    ).strip()

    if not is_valid_url(url):
        return jsonify({
            "error":
                "Invalid scan URL."
        }), 400

    raw_features = payload.get(
        "features",
        {}
    )

    normalized_features = (
        normalize_features(
            raw_features
            if isinstance(
                raw_features,
                dict
            )
            else {}
        )
    )

    findings = payload.get(
        "findings",
        []
    )

    if not isinstance(findings, list):
        findings = []

    prediction = (
        payload.get("riskLevel")
        or payload.get("prediction")
        or "UNKNOWN"
    )

    scan_record = {
        "id":
            payload.get("id")
            or str(uuid.uuid4()),

        "url":
            url,

        "title":
            payload.get(
                "title",
                ""
            ),

        "timestamp":
            payload.get(
                "timestamp",
                int(time.time() * 1000)
            ),

        "activeScanUsed":
            bool(
                payload.get(
                    "activeScanUsed",
                    False
                )
            ),

        "prediction":
            str(prediction).upper(),

        "riskLevel":
            str(prediction).upper(),

        "confidence":
            float(
                payload.get(
                    "confidence",
                    0.0
                )
                or 0.0
            ),

        "riskScore":
            payload.get(
                "riskScore"
            ),

        "securityScore":
            payload.get(
                "securityScore",
                payload.get("score")
            ),

        "features":
            normalized_features,

        "findings":
            findings,

        "checksPassed":
            payload.get(
                "checksPassed",
                0
            ),

        "checksTotal":
            payload.get(
                "checksTotal",
                0
            ),

        "technologies":
            payload.get(
                "technologies",
                []
            ),
    }

    config = current_app.config[
        "APP_CONFIG"
    ]

    try:
        database.insert_scan(
            config,
            scan_record
        )

    except Exception as error:

        current_app.logger.exception(
            "Failed to save scan"
        )

        return jsonify({
            "error":
                "Failed to save scan.",

            "details":
                str(error)
        }), 500

    return jsonify({
        "status": "saved",
        "id": scan_record["id"]
    })


# ============================================================
# Optional server-side URL scanning
# ============================================================

@api_bp.route(
    "/scan/url",
    methods=["POST"]
)
def scan_url():

    payload = request.get_json(
        force=True,
        silent=True
    ) or {}

    url = str(
        payload.get(
            "url",
            ""
        )
    ).strip()

    active = bool(
        payload.get(
            "active",
            False
        )
    )

    if not is_valid_url(url):

        return jsonify({
            "error":
                "Invalid URL. URL must begin "
                "with http:// or https://"
        }), 400

    # Active server scanning is local-lab only.
    if (
        active
        and not is_local_training_lab(url)
    ):
        return jsonify({
            "error":
                "Active scanning is restricted "
                "to localhost/127.0.0.1 "
                "training labs."
        }), 403

    predictor = current_app.config[
        "PREDICTOR"
    ]

    if not predictor.is_ready():

        return jsonify({
            "error":
                "Decision Tree model has "
                "not been trained yet.",

            "modelReady":
                False
        }), 503

    try:
        passive_result = (
            server_scanner.passive_scan(
                url
            )
        )

        active_result = None

        if active:
            active_result = (
                server_scanner.active_scan(
                    url
                )
            )

    except Exception as error:

        current_app.logger.exception(
            "Server-side scan failed"
        )

        return jsonify({
            "error":
                "Server-side scan failed.",

            "details":
                str(error)
        }), 500

    findings = list(
        passive_result.get(
            "findings",
            []
        )
    )

    if active_result:
        findings.extend(
            active_result.get(
                "findings",
                []
            )
        )

    headers = passive_result.get(
        "headers",
        {}
    )

    sql_results = (
        active_result.get(
            "sql_results",
            []
        )
        if active_result
        else []
    )

    xss_results = (
        active_result.get(
            "xss_results",
            []
        )
        if active_result
        else []
    )

    directory_results = (
        active_result.get(
            "directory_results",
            []
        )
        if active_result
        else []
    )

    query_count = len(
        parse_qsl(
            urlparse(url).query,
            keep_blank_values=True
        )
    )

    # Server scanner may not have every browser-level
    # feature. normalize_features() fills missing
    # values with safe defaults.
    raw_features = {
        "https":
            1
            if passive_result.get(
                "is_https",
                False
            )
            else 0,

        "csp":
            1
            if "content-security-policy"
            in headers
            else 0,

        "hsts":
            1
            if "strict-transport-security"
            in headers
            else 0,

        "x_frame_options":
            1
            if "x-frame-options"
            in headers
            else 0,

        "x_content_type_options":
            1
            if "x-content-type-options"
            in headers
            else 0,

        "num_forms":
            passive_result.get(
                "num_forms",
                0
            ),

        "password_fields":
            passive_result.get(
                "password_fields",
                0
            ),

        "url_length":
            len(url),

        "query_parameters":
            query_count,

        "external_scripts":
            passive_result.get(
                "external_scripts",
                0
            ),

        "inline_scripts":
            passive_result.get(
                "inline_scripts",
                0
            ),

        "http_status":
            passive_result.get(
                "status_code",
                200
            ),

        "sql_error_indicator":
            1
            if any(
                result.get(
                    "sqlErrorDetected"
                )
                for result
                in sql_results
            )
            else 0,

        "reflected_payload_indicator":
            1
            if any(
                result.get(
                    "reflectedUnescaped"
                )
                for result
                in xss_results
            )
            else 0,

        "server_error_indicator":
            1
            if passive_result.get(
                "status_code",
                200
            ) >= 500
            else 0,

        "mixed_content_count":
            passive_result.get(
                "mixed_content_count",
                0
            ),

        "exposed_paths":
            len([
                result
                for result
                in directory_results
                if result.get(
                    "exists",
                    False
                )
            ]),

        # Important:
        # A password field is only a page feature.
        # There is NO brute-force vulnerability
        # feature here.
        "login_surface":
            1
            if passive_result.get(
                "password_fields",
                0
            ) > 0
            else 0,
    }

    features = normalize_features(
        raw_features
    )

    prediction = predictor.predict(
        features
    )

    scan_record = {
        "id":
            str(uuid.uuid4()),

        "url":
            url,

        "title":
            "",

        "timestamp":
            int(
                time.time() * 1000
            ),

        "activeScanUsed":
            active,

        "prediction":
            prediction["label"],

        "riskLevel":
            prediction["label"],

        "confidence":
            prediction["confidence"],

        "riskScore":
            prediction["risk_score"],

        "securityScore":
            prediction["security_score"],

        "features":
            features,

        "findings":
            findings,
    }

    config = current_app.config[
        "APP_CONFIG"
    ]

    database.insert_scan(
        config,
        scan_record
    )

    return jsonify({
        **scan_record,

        "probabilities":
            prediction[
                "probabilities"
            ],

        "recommendations":
            build_recommendations(
                findings
            ),

        "summary":
            summarize_prediction(
                prediction["label"]
            ),

        "modelReady":
            True
    })


# ============================================================
# Scan history
# ============================================================

@api_bp.route(
    "/scan/history",
    methods=["GET"]
)
def scan_history():

    limit = safe_integer(
        request.args.get(
            "limit"
        ),
        default=50,
        minimum=1,
        maximum=1000
    )

    offset = safe_integer(
        request.args.get(
            "offset"
        ),
        default=0,
        minimum=0,
        maximum=100000
    )

    config = current_app.config[
        "APP_CONFIG"
    ]

    history = (
        database.fetch_scan_history(
            config,
            limit=limit,
            offset=offset
        )
    )

    return jsonify({
        "scans":
            history,

        "count":
            len(history)
    })


@api_bp.route(
    "/scan/<scan_id>",
    methods=["GET"]
)
def get_scan(scan_id):

    config = current_app.config[
        "APP_CONFIG"
    ]

    scan = database.fetch_scan_by_id(
        config,
        scan_id
    )

    if not scan:

        return jsonify({
            "error":
                "Scan not found"
        }), 404

    return jsonify(scan)


# ============================================================
# Dashboard statistics
# ============================================================

@api_bp.route(
    "/dashboard/stats",
    methods=["GET"]
)
def dashboard_stats():

    config = current_app.config[
        "APP_CONFIG"
    ]

    stats = (
        database.fetch_dashboard_stats(
            config
        )
    )

    return jsonify(stats)


# ============================================================
# Reports
# ============================================================

@api_bp.route(
    "/report/<scan_id>",
    methods=["GET"]
)
def report(scan_id):

    fmt = (
        request.args.get(
            "format",
            "pdf"
        )
        .lower()
    )

    config = current_app.config[
        "APP_CONFIG"
    ]

    scan = (
        database.fetch_scan_by_id(
            config,
            scan_id
        )
    )

    if not scan:

        return jsonify({
            "error":
                "Scan not found"
        }), 404

    reports_dir = ensure_dir(
        config.REPORTS_DIR
    )

    safe_id = sanitize_filename(
        scan_id
    )

    if fmt == "csv":

        output_path = os.path.join(
            reports_dir,
            f"{safe_id}.csv"
        )

        generate_csv_report(
            scan,
            output_path
        )

        return send_file(
            output_path,
            as_attachment=True,
            download_name=
                f"vulnscan_{safe_id}.csv"
        )

    output_path = os.path.join(
        reports_dir,
        f"{safe_id}.pdf"
    )

    generate_pdf_report(
        scan,
        output_path
    )

    return send_file(
        output_path,
        as_attachment=True,
        download_name=
            f"vulnscan_{safe_id}.pdf"
    )


@api_bp.route(
    "/report/history/csv",
    methods=["GET"]
)
def report_history_csv():

    config = current_app.config[
        "APP_CONFIG"
    ]

    scans = (
        database.fetch_scan_history(
            config,
            limit=1000,
            offset=0
        )
    )

    reports_dir = ensure_dir(
        config.REPORTS_DIR
    )

    output_path = os.path.join(
        reports_dir,
        "scan_history_export.csv"
    )

    generate_history_csv(
        scans,
        output_path
    )

    return send_file(
        output_path,
        as_attachment=True,
        download_name=
            "scan_history_export.csv"
    )


# ============================================================
# Dashboard
# ============================================================

@dashboard_bp.route("/")
def dashboard_root():

    return redirect(
        "/dashboard"
    )


@dashboard_bp.route(
    "/dashboard"
)
def dashboard_index():

    config = current_app.config[
        "APP_CONFIG"
    ]

    return send_from_directory(
        config.DASHBOARD_DIR,
        "dashboard.html"
    )


@dashboard_bp.route(
    "/dashboard/<path:filename>"
)
def dashboard_assets(filename):

    config = current_app.config[
        "APP_CONFIG"
    ]

    return send_from_directory(
        config.DASHBOARD_DIR,
        filename
    )