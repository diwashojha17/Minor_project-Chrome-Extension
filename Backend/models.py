"""
models.py

Lightweight Python data models used across the backend.

These are plain dataclasses, not database ORM models.
"""

import time

from dataclasses import (
    dataclass,
    field,
)

from typing import (
    List,
    Dict,
    Any,
    Optional,
)


# ============================================================
# Finding
# ============================================================

@dataclass
class Finding:
    type: str

    severity: str

    message: str

    # detected | potential | informational
    status: str = "detected"


    def to_dict(
        self
    ) -> Dict[str, Any]:

        return {
            "type":
                self.type,

            "severity":
                self.severity,

            "message":
                self.message,

            "status":
                self.status,
        }


# ============================================================
# ML / scanner features
# ============================================================

@dataclass
class ScanFeatures:

    # --------------------------------------------------------
    # Transport / security headers
    # --------------------------------------------------------

    https: int = 0

    csp: int = 0

    hsts: int = 0

    x_frame_options: int = 0

    x_content_type_options: int = 0


    # --------------------------------------------------------
    # Cookies
    # --------------------------------------------------------

    secure_cookie: int = 0

    httponly_cookie: int = 0

    samesite_cookie: int = 0


    # --------------------------------------------------------
    # Page structure
    # --------------------------------------------------------

    num_forms: int = 0

    password_fields: int = 0

    url_length: int = 0

    query_parameters: int = 0

    external_scripts: int = 0

    inline_scripts: int = 0


    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    http_status: int = 200


    # --------------------------------------------------------
    # Active vulnerability evidence
    # --------------------------------------------------------

    sql_error_indicator: int = 0

    reflected_payload_indicator: int = 0

    server_error_indicator: int = 0

    mixed_content_count: int = 0

    exposed_paths: int = 0

    blind_sqli_indicator: int = 0


    # --------------------------------------------------------
    # Passive security indicators
    # --------------------------------------------------------

    dom_xss_indicator: int = 0

    csrf_missing_token: int = 0

    unsafe_upload_indicator: int = 0

    weak_session_indicator: int = 0

    weak_csp_indicator: int = 0


    # --------------------------------------------------------
    # Redirect evidence
    # --------------------------------------------------------

    open_redirect_indicator: int = 0


    # --------------------------------------------------------
    # Informational attack surfaces
    #
    # These DO NOT mean a vulnerability was confirmed.
    # --------------------------------------------------------

    command_input_surface: int = 0

    file_path_input_surface: int = 0

    stored_input_surface: int = 0

    file_upload_surface: int = 0

    # Important:
    # login_surface = 1 only means a login form exists.
    # It DOES NOT mean brute-force vulnerability.
    login_surface: int = 0

    api_surface: int = 0


    @staticmethod
    def from_dict(
        data: Dict[str, Any]
    ) -> "ScanFeatures":

        if not isinstance(
            data,
            dict
        ):
            data = {}

        valid_keys = (
            ScanFeatures
            .__dataclass_fields__
            .keys()
        )

        filtered = {
            key: value

            for key, value
            in data.items()

            if key in valid_keys
        }

        return ScanFeatures(
            **filtered
        )


    def to_dict(
        self
    ) -> Dict[str, Any]:

        return {
            key:
                getattr(
                    self,
                    key
                )

            for key
            in self.__dataclass_fields__
        }


# ============================================================
# Full scan record
# ============================================================

@dataclass
class ScanRecord:

    id: str

    url: str

    title: str

    prediction: str

    confidence: float

    features: ScanFeatures


    findings: List[Finding] = (
        field(
            default_factory=list
        )
    )


    active_scan_used: bool = False


    timestamp: int = field(
        default_factory=lambda:
            int(
                time.time() * 1000
            )
    )


    risk_score: Optional[float] = None

    security_score: Optional[float] = None


    checks_passed: int = 0

    checks_total: int = 0


    technologies: List[str] = field(
        default_factory=list
    )


    def to_dict(
        self
    ) -> Dict[str, Any]:

        return {
            "id":
                self.id,

            "url":
                self.url,

            "title":
                self.title,

            "timestamp":
                self.timestamp,

            "activeScanUsed":
                self.active_scan_used,

            "prediction":
                self.prediction,

            "riskLevel":
                self.prediction,

            "confidence":
                self.confidence,

            "riskScore":
                self.risk_score,

            "securityScore":
                self.security_score,

            "features":
                self.features.to_dict(),

            "findings": [
                finding.to_dict()

                for finding
                in self.findings
            ],

            "checksPassed":
                self.checks_passed,

            "checksTotal":
                self.checks_total,

            "technologies":
                self.technologies,
        }