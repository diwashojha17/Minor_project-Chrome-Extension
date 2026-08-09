"""
analyzer.py

Converts scanner findings and Decision Tree predictions
into human-readable summaries and recommendations.

IMPORTANT:
The overall security score comes from the Decision Tree
prediction, not from hard-coded finding deductions.
"""

from typing import (
    List,
    Dict,
    Optional,
    Any,
)


# ============================================================
# Recommendations
# ============================================================

RECOMMENDATION_MAP = {

    "HTTPS":
        "Enable HTTPS using a valid TLS certificate and redirect HTTP traffic to HTTPS.",

    "HEADER":
        "Configure the recommended HTTP security headers, including CSP, HSTS, X-Frame-Options and X-Content-Type-Options.",

    "COOKIE":
        "Configure session and authentication cookies with appropriate Secure, HttpOnly and SameSite attributes.",

    "MIXED_CONTENT":
        "Replace insecure HTTP resources with HTTPS resources.",

    "FORM":
        "Ensure sensitive forms submit only over secure HTTPS connections.",

    "WEAK_CSP":
        "Strengthen the Content-Security-Policy and avoid unsafe-inline or unsafe-eval where possible.",

    "CSRF":
        "Use unpredictable server-generated CSRF tokens for state-changing forms and validate them server-side.",

    "FILE_UPLOAD":
        "Validate uploaded file type, size and content; store uploads outside executable locations and rename files safely.",

    "DOM_XSS":
        "Avoid unsafe DOM sinks such as innerHTML when processing untrusted input; prefer safe DOM APIs and output encoding.",

    "EXPOSED_PATH":
        "Review exposed paths and prevent public access to sensitive files or directories such as .git, .env and backups.",

    "XSS":
        "Validate input and contextually encode output before inserting user-controlled content into HTML.",

    "SQLI":
        "Use parameterized SQL queries or prepared statements instead of constructing queries with user input.",

    "BLIND_SQLI":
        "Use parameterized queries and validate database access paths. Investigate response differences found during testing.",

    "OPEN_REDIRECT":
        "Validate redirect destinations against an explicit allow-list and avoid directly trusting user-controlled redirect URLs.",
}


# ============================================================
# Decision Tree risk summaries
# ============================================================

PREDICTION_SUMMARY = {

    "SAFE":
        "No major risk was predicted by the Decision Tree. Review individual findings and continue periodic monitoring.",

    "LOW":
        "The Decision Tree predicts a low overall security risk. Minor hardening opportunities may still exist.",

    "MEDIUM":
        "The Decision Tree predicts a medium security risk. Review and remediate the identified weaknesses.",

    "HIGH":
        "The Decision Tree predicts a high security risk. Significant findings should be prioritized for remediation.",

    "CRITICAL":
        "The Decision Tree predicts a critical security risk. High-priority findings require immediate investigation.",


    # --------------------------------------------------------
    # Legacy labels
    #
    # Kept so your previous database records can still
    # display understandable text.
    # --------------------------------------------------------

    "SECURE":
        "This is a legacy scan classification indicating relatively low observed risk.",

    "LOW RISK":
        "This is a legacy low-risk classification.",

    "MEDIUM RISK":
        "This is a legacy medium-risk classification.",

    "HIGH RISK":
        "This is a legacy high-risk classification.",

    "XSS RISK":
        "This older scan indicated possible Cross-Site Scripting risk.",

    "SQL INJECTION RISK":
        "This older scan indicated possible SQL Injection risk.",

    "CLICKJACKING RISK":
        "This older scan indicated missing or insufficient frame protection.",

    "INFORMATION DISCLOSURE":
        "This older scan indicated possible information exposure.",
}


# ============================================================
# Build recommendations
# ============================================================

def build_recommendations(
    findings: List[Dict]
) -> List[str]:
    """
    Convert unique finding types into remediation advice.
    """

    if not isinstance(findings, list):
        return []

    recommendations = []

    seen_types = set()

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        finding_type = str(
            finding.get(
                "type",
                ""
            )
        ).strip().upper()

        if not finding_type:
            continue

        if finding_type in seen_types:
            continue

        seen_types.add(
            finding_type
        )

        recommendation = (
            RECOMMENDATION_MAP.get(
                finding_type
            )
        )

        if recommendation:
            recommendations.append(
                recommendation
            )

    return recommendations


# ============================================================
# Prediction summary
# ============================================================

def summarize_prediction(
    prediction_label: str
) -> str:
    """Return a human-readable Decision Tree summary."""

    label = str(
        prediction_label or ""
    ).strip().upper()

    return PREDICTION_SUMMARY.get(
        label,

        "Review the detected and potential findings for additional security information."
    )


# ============================================================
# Security score
# ============================================================

def compute_security_score(
    risk_score: Any
) -> Optional[float]:
    """
    Convert the Decision Tree's 0-100 risk score into
    a 0-100 security score.

        risk score = 80
        security score = 20

    This function DOES NOT calculate risk from hard-coded
    finding severity deductions.
    """

    if risk_score is None:
        return None

    try:
        risk = float(
            risk_score
        )

    except (
        TypeError,
        ValueError
    ):
        return None

    risk = max(
        0.0,
        min(
            100.0,
            risk
        )
    )

    security_score = (
        100.0 - risk
    )

    return round(
        security_score,
        2
    )