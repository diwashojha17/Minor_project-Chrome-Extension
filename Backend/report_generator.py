"""
report_generator.py

Generates PDF and CSV security reports.

The overall risk/security score comes from the
Decision Tree prediction stored with the scan.
"""

import csv
import json

from datetime import datetime

from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4

from reportlab.lib import colors

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)

from reportlab.lib.units import cm

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from analyzer import (
    build_recommendations,
    summarize_prediction,
    compute_security_score,
)


# ============================================================
# Helpers
# ============================================================

def _safe_json(
    value,
    default
):

    if value is None:
        return default

    if not isinstance(
        value,
        str
    ):
        return value

    try:
        return json.loads(
            value
        )

    except (
        json.JSONDecodeError,
        TypeError
    ):
        return default


def _get_findings(scan):

    findings = scan.get(
        "findings"
    )

    if isinstance(findings, list):
        return findings

    return _safe_json(
        scan.get(
            "findings_json"
        ),
        []
    )


def _get_features(scan):

    features = scan.get(
        "features"
    )

    if isinstance(features, dict):
        return features

    return _safe_json(
        scan.get(
            "features_json"
        ),
        {}
    )


def _get_technologies(scan):

    technologies = scan.get(
        "technologies"
    )

    if isinstance(
        technologies,
        list
    ):
        return technologies

    return _safe_json(
        scan.get(
            "technologies_json"
        ),
        []
    )


def _get_risk_score(scan):

    value = scan.get(
        "riskScore"
    )

    if value is None:
        value = scan.get(
            "risk_score"
        )

    try:
        return (
            float(value)
            if value is not None
            else None
        )

    except (
        TypeError,
        ValueError
    ):
        return None


def _get_security_score(scan):

    value = scan.get(
        "securityScore"
    )

    if value is None:
        value = scan.get(
            "security_score"
        )

    if value is not None:

        try:
            return float(value)

        except (
            TypeError,
            ValueError
        ):
            pass

    # Safe fallback:
    # derive security score only from the
    # Decision Tree risk score.
    risk_score = _get_risk_score(
        scan
    )

    return compute_security_score(
        risk_score
    )


def _format_timestamp(value):

    try:
        timestamp = float(
            value
        )

        # Stored timestamps use milliseconds.
        if timestamp > 10_000_000_000:
            timestamp /= 1000

        return datetime.fromtimestamp(
            timestamp
        ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        TypeError,
        ValueError,
        OSError
    ):
        return "Unknown"


def _text(value):
    """Escape text before using it in ReportLab Paragraph."""

    return escape(
        str(
            value
            if value is not None
            else ""
        )
    )


# ============================================================
# PDF report
# ============================================================

def generate_pdf_report(
    scan: dict,
    output_path: str
):

    findings = _get_findings(
        scan
    )

    features = _get_features(
        scan
    )

    technologies = _get_technologies(
        scan
    )

    risk_score = _get_risk_score(
        scan
    )

    security_score = (
        _get_security_score(
            scan
        )
    )


    document = SimpleDocTemplate(
        output_path,

        pagesize=A4,

        topMargin=1.5 * cm,

        bottomMargin=1.5 * cm,

        leftMargin=1.5 * cm,

        rightMargin=1.5 * cm,
    )


    styles = (
        getSampleStyleSheet()
    )


    title_style = ParagraphStyle(
        "ScannerTitle",

        parent=styles["Title"],

        textColor=colors.HexColor(
            "#0f172a"
        ),

        fontSize=20,

        spaceAfter=12,
    )


    heading_style = ParagraphStyle(
        "ScannerHeading",

        parent=styles[
            "Heading2"
        ],

        textColor=colors.HexColor(
            "#0369a1"
        ),

        spaceBefore=8,

        spaceAfter=8,
    )


    normal_style = styles[
        "Normal"
    ]


    small_style = ParagraphStyle(
        "Small",

        parent=normal_style,

        fontSize=8,

        leading=10,
    )


    story = []


    # --------------------------------------------------------
    # Title
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "AI Web Vulnerability Scan Report",
            title_style
        )
    )


    # --------------------------------------------------------
    # Metadata
    # --------------------------------------------------------

    prediction = str(
        scan.get(
            "prediction",
            "UNKNOWN"
        )
    ).upper()


    confidence = scan.get(
        "confidence",
        0
    )


    try:
        confidence_text = (
            f"{float(confidence) * 100:.1f}%"
        )

    except (
        TypeError,
        ValueError
    ):
        confidence_text = "N/A"


    risk_text = (
        f"{risk_score:.1f} / 100"
        if risk_score is not None
        else "N/A"
    )


    security_text = (
        f"{security_score:.1f} / 100"
        if security_score is not None
        else "N/A"
    )


    active_scan = (
        scan.get(
            "activeScanUsed"
        )

        if "activeScanUsed"
        in scan

        else bool(
            scan.get(
                "active_scan_used",
                False
            )
        )
    )


    metadata = [
        [
            "Target URL",

            Paragraph(
                _text(
                    scan.get(
                        "url",
                        ""
                    )
                ),
                small_style
            )
        ],

        [
            "Scan Date",

            _format_timestamp(
                scan.get(
                    "timestamp"
                )
            )
        ],

        [
            "Risk Classification",

            prediction
        ],

        [
            "Confidence",

            confidence_text
        ],

        [
            "Risk Score",

            risk_text
        ],

        [
            "Security Score",

            security_text
        ],

        [
            "Active Scan",

            (
                "Yes"
                if active_scan
                else "No"
            )
        ],
    ]


    metadata_table = Table(
        metadata,

        colWidths=[
            4.5 * cm,
            12.5 * cm
        ]
    )


    metadata_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor(
                    "#e2e8f0"
                )
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor(
                    "#cbd5e1"
                )
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
        ])
    )


    story.append(
        metadata_table
    )

    story.append(
        Spacer(
            1,
            16
        )
    )


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Decision Tree Summary",
            heading_style
        )
    )


    story.append(
        Paragraph(
            _text(
                summarize_prediction(
                    prediction
                )
            ),

            normal_style
        )
    )


    story.append(
        Spacer(
            1,
            12
        )
    )


    # --------------------------------------------------------
    # Findings
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Security Findings",
            heading_style
        )
    )


    if findings:

        finding_rows = [[
            "Severity",
            "Status",
            "Type",
            "Finding"
        ]]


        for finding in findings:

            finding_rows.append([
                Paragraph(
                    _text(
                        finding.get(
                            "severity",
                            ""
                        )
                    ).title(),
                    small_style
                ),

                Paragraph(
                    _text(
                        finding.get(
                            "status",
                            "detected"
                        )
                    ).title(),
                    small_style
                ),

                Paragraph(
                    _text(
                        finding.get(
                            "type",
                            ""
                        )
                    ),
                    small_style
                ),

                Paragraph(
                    _text(
                        finding.get(
                            "message",
                            ""
                        )
                    ),
                    small_style
                ),
            ])


        finding_table = Table(
            finding_rows,

            colWidths=[
                2 * cm,
                2.5 * cm,
                3 * cm,
                9.5 * cm
            ],

            repeatRows=1
        )


        finding_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#0f172a"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor(
                        "#cbd5e1"
                    )
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5
                ),
            ])
        )


        story.append(
            finding_table
        )

    else:

        story.append(
            Paragraph(
                "No scanner findings were recorded.",
                normal_style
            )
        )


    story.append(
        Spacer(
            1,
            16
        )
    )


    # --------------------------------------------------------
    # Recommendations
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "Recommendations",
            heading_style
        )
    )


    recommendations = (
        build_recommendations(
            findings
        )
    )


    if recommendations:

        for (
            index,
            recommendation
        ) in enumerate(
            recommendations,
            start=1
        ):

            story.append(
                Paragraph(
                    f"{index}. "
                    + _text(
                        recommendation
                    ),

                    normal_style
                )
            )

            story.append(
                Spacer(
                    1,
                    4
                )
            )

    else:

        story.append(
            Paragraph(
                "No specific remediation recommendation is available for this scan.",
                normal_style
            )
        )


    # --------------------------------------------------------
    # Technology fingerprint
    # --------------------------------------------------------

    story.append(
        Spacer(
            1,
            16
        )
    )


    story.append(
        Paragraph(
            "Detected Technologies",
            heading_style
        )
    )


    if technologies:

        story.append(
            Paragraph(
                _text(
                    ", ".join(
                        str(item)

                        for item
                        in technologies
                    )
                ),

                normal_style
            )
        )

    else:

        story.append(
            Paragraph(
                "No technology fingerprint information was recorded.",
                normal_style
            )
        )


    # --------------------------------------------------------
    # Features
    # --------------------------------------------------------

    story.append(
        Spacer(
            1,
            16
        )
    )


    story.append(
        Paragraph(
            "Extracted ML Feature Snapshot",
            heading_style
        )
    )


    feature_rows = [[
        "Feature",
        "Value"
    ]]


    for (
        feature,
        value
    ) in features.items():

        feature_rows.append([
            Paragraph(
                _text(feature),
                small_style
            ),

            Paragraph(
                _text(value),
                small_style
            )
        ])


    feature_table = Table(
        feature_rows,

        colWidths=[
            9 * cm,
            8 * cm
        ],

        repeatRows=1
    )


    feature_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#0369a1"
                )
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor(
                    "#cbd5e1"
                )
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
        ])
    )


    story.append(
        feature_table
    )


    document.build(
        story
    )

    return output_path


# ============================================================
# Individual CSV report
# ============================================================

def generate_csv_report(
    scan: dict,
    output_path: str
):

    findings = _get_findings(
        scan
    )

    risk_score = _get_risk_score(
        scan
    )

    security_score = (
        _get_security_score(
            scan
        )
    )


    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(
            file
        )


        writer.writerow([
            "url",
            scan.get(
                "url",
                ""
            )
        ])


        writer.writerow([
            "prediction",
            scan.get(
                "prediction",
                ""
            )
        ])


        writer.writerow([
            "confidence",
            scan.get(
                "confidence",
                ""
            )
        ])


        writer.writerow([
            "risk_score",
            (
                risk_score
                if risk_score is not None
                else ""
            )
        ])


        writer.writerow([
            "security_score",
            (
                security_score
                if security_score is not None
                else ""
            )
        ])


        writer.writerow([])


        writer.writerow([
            "severity",
            "status",
            "type",
            "message"
        ])


        for finding in findings:

            writer.writerow([
                finding.get(
                    "severity",
                    ""
                ),

                finding.get(
                    "status",
                    "detected"
                ),

                finding.get(
                    "type",
                    ""
                ),

                finding.get(
                    "message",
                    ""
                ),
            ])


    return output_path


# ============================================================
# Scan history CSV
# ============================================================

def generate_history_csv(
    scans: list,
    output_path: str
):

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(
            file
        )


        writer.writerow([
            "id",
            "url",
            "timestamp",
            "prediction",
            "confidence",
            "risk_score",
            "security_score",
            "active_scan_used",
        ])


        for scan in scans:

            writer.writerow([
                scan.get(
                    "id",
                    ""
                ),

                scan.get(
                    "url",
                    ""
                ),

                scan.get(
                    "timestamp",
                    ""
                ),

                scan.get(
                    "prediction",
                    ""
                ),

                scan.get(
                    "confidence",
                    ""
                ),

                scan.get(
                    "riskScore",
                    scan.get(
                        "risk_score",
                        ""
                    )
                ),

                scan.get(
                    "securityScore",
                    scan.get(
                        "security_score",
                        ""
                    )
                ),

                scan.get(
                    "activeScanUsed",
                    scan.get(
                        "active_scan_used",
                        False
                    )
                ),
            ])


    return output_path