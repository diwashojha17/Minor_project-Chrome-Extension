"""
utils.py

Small shared helper functions for the Flask backend.
"""

import os
import re

from urllib.parse import urlparse


# ============================================================
# Filename safety
# ============================================================

def sanitize_filename(
    name: str
) -> str:
    """
    Remove unsafe filename characters.
    """

    value = str(
        name or ""
    )

    safe = re.sub(
        r"[^a-zA-Z0-9._-]",
        "_",
        value
    )

    safe = safe.strip(
        "._"
    )

    if not safe:
        safe = "report"

    return safe[:100]


# ============================================================
# Directory helper
# ============================================================

def ensure_dir(
    path: str
) -> str:
    """
    Create a directory if it does not exist.
    """

    absolute_path = os.path.abspath(
        path
    )

    os.makedirs(
        absolute_path,
        exist_ok=True
    )

    return absolute_path


# ============================================================
# URL validation
# ============================================================

def is_valid_url(
    url: str
) -> bool:
    """
    Accept only complete HTTP/HTTPS URLs.
    """

    if not isinstance(
        url,
        str
    ):
        return False

    url = url.strip()

    if not url:
        return False

    try:
        parsed = urlparse(
            url
        )

        return (
            parsed.scheme.lower()
            in {
                "http",
                "https"
            }

            and bool(
                parsed.hostname
            )
        )

    except ValueError:
        return False


# ============================================================
# Local training lab
# ============================================================

def is_local_training_url(
    url: str
) -> bool:
    """
    Return True only for local training targets such as DVWA.
    """

    if not is_valid_url(
        url
    ):
        return False

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

    except ValueError:
        return False