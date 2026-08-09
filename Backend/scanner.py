"""
scanner.py

Optional server-side scanner used by /api/scan/url.

Passive scan:
    May inspect normal HTTP/HTTPS URLs.

Active scan:
    Restricted to localhost / 127.0.0.1 / ::1
    for authorized training environments such as DVWA.

IMPORTANT:
A password/login form is informational only.
It is NOT a brute-force vulnerability.
"""

import re
import requests

from urllib.parse import (
    urlparse,
    urlsplit,
    urlunsplit,
    urlencode,
    parse_qsl,
)


REQUEST_TIMEOUT = 8

USER_AGENT = (
    "AI-Web-Vulnerability-Scanner/1.0 "
    "(educational-project)"
)


LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
}


SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "warning: mysql",
    "mysqli_sql_exception",
    "ora-01756",
    "sqlite3.operationalerror",
    "unclosed quotation mark",
    "pg_query",
    "postgresql query failed",
    "syntax error near",
]


SAFE_XSS_MARKER = (
    "<vulnscan-probe-12345>"
)


COMMON_DIRECTORIES = [
    "/admin",
    "/backup",
    "/.git/",
    "/.env",
    "/config",
    "/test",
    "/uploads",
]


REDIRECT_PARAMETERS = {
    "redirect",
    "url",
    "next",
    "return",
    "dest",
}


COMMAND_PARAMETER_NAMES = {
    "ip",
    "host",
    "hostname",
    "cmd",
    "command",
    "ping",
}


FILE_PARAMETER_NAMES = {
    "page",
    "file",
    "path",
    "template",
    "include",
}


# ============================================================
# Helpers
# ============================================================

def _session():
    session = requests.Session()

    session.headers.update({
        "User-Agent":
            USER_AGENT
    })

    return session


def _assert_local_lab(url):
    """Prevent active scanning outside the local lab."""

    hostname = (
        urlparse(url)
        .hostname
    )

    if hostname not in LOCAL_HOSTS:
        raise PermissionError(
            "Active scanning is restricted to "
            "localhost/127.0.0.1 training labs."
        )


def _replace_parameter(
    base_url,
    parameter,
    value
):
    parts = urlsplit(
        base_url
    )

    query = dict(
        parse_qsl(
            parts.query,
            keep_blank_values=True
        )
    )

    query[parameter] = value

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(query),
        parts.fragment,
    ))


def _get_set_cookie_headers(response):

    try:
        if (
            response.raw
            and hasattr(
                response.raw.headers,
                "get_all"
            )
        ):
            return (
                response.raw.headers.get_all(
                    "Set-Cookie"
                )
                or []
            )

    except Exception:
        pass

    value = response.headers.get(
        "Set-Cookie"
    )

    return [value] if value else []


# ============================================================
# Technology detection
# ============================================================

def _detect_technologies(
    html,
    headers
):
    technologies = []

    server = headers.get(
        "server"
    )

    if server:
        technologies.append(
            server
        )

    generator = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        html,
        re.IGNORECASE
    )

    if generator:
        technologies.append(
            generator.group(1)
        )

    html_lower = html.lower()

    technology_patterns = {
        "jQuery":
            r'jquery(?:\.min)?\.js',

        "Bootstrap":
            r'bootstrap(?:\.min)?\.(?:js|css)',

        "React":
            r'react(?:\.production)?(?:\.min)?\.js',

        "Angular":
            r'angular(?:\.min)?\.js',

        "Vue.js":
            r'vue(?:\.min)?\.js',

        "WordPress":
            r'wp-content|wp-includes',

        "Next.js":
            r'__next|/_next/',
    }

    for (
        technology,
        pattern
    ) in technology_patterns.items():

        if re.search(
            pattern,
            html_lower
        ):
            technologies.append(
                technology
            )

    # Remove duplicates while preserving order.
    return list(
        dict.fromkeys(
            technologies
        )
    )


# ============================================================
# Passive scan
# ============================================================

def passive_scan(url: str) -> dict:
    """
    Perform read-only checks against a webpage.
    """

    findings = []

    session = _session()

    response = session.get(
        url,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True
    )

    headers = {
        key.lower(): value
        for key, value
        in response.headers.items()
    }

    html = response.text or ""

    final_url = (
        response.url or url
    )

    is_https = (
        urlparse(
            final_url
        ).scheme.lower()
        == "https"
    )


    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if not is_https:

        findings.append({
            "type":
                "HTTPS",

            "severity":
                "high",

            "status":
                "detected",

            "message":
                "Site is not served over HTTPS."
        })


    # --------------------------------------------------------
    # Security headers
    # --------------------------------------------------------

    header_checks = {

        "content-security-policy":
            "Content-Security-Policy (CSP) header missing.",

        "x-content-type-options":
            "X-Content-Type-Options header missing.",

        "referrer-policy":
            "Referrer-Policy header missing.",

        "permissions-policy":
            "Permissions-Policy header missing.",
    }

    for (
        header,
        message
    ) in header_checks.items():

        if not headers.get(header):

            findings.append({
                "type":
                    "HEADER",

                "severity":
                    "medium",

                "status":
                    "detected",

                "message":
                    message
            })


    # HSTS is relevant to HTTPS pages.
    if (
        is_https
        and not headers.get(
            "strict-transport-security"
        )
    ):

        findings.append({
            "type":
                "HEADER",

            "severity":
                "medium",

            "status":
                "detected",

            "message":
                "HTTP Strict-Transport-Security (HSTS) header missing."
        })


    # Frame protection can come from XFO or CSP.
    csp = headers.get(
        "content-security-policy",
        ""
    )

    has_frame_ancestors = (
        "frame-ancestors"
        in csp.lower()
    )

    if (
        not headers.get(
            "x-frame-options"
        )
        and not has_frame_ancestors
    ):

        findings.append({
            "type":
                "HEADER",

            "severity":
                "medium",

            "status":
                "detected",

            "message":
                "Frame protection missing (X-Frame-Options or CSP frame-ancestors)."
        })


    # --------------------------------------------------------
    # Weak CSP
    # --------------------------------------------------------

    weak_csp = False

    if csp:

        csp_lower = (
            csp.lower()
        )

        weak_csp = (
            "'unsafe-inline'"
            in csp_lower

            or "'unsafe-eval'"
            in csp_lower
        )

        if weak_csp:

            findings.append({
                "type":
                    "WEAK_CSP",

                "severity":
                    "medium",

                "status":
                    "potential",

                "message":
                    "CSP contains unsafe-inline or unsafe-eval."
            })


    # --------------------------------------------------------
    # Cookie security
    # --------------------------------------------------------

    cookie_headers = (
        _get_set_cookie_headers(
            response
        )
    )

    insecure_cookie = 0
    missing_httponly = 0
    missing_samesite = 0

    for raw_cookie in cookie_headers:

        parts = [
            part.strip().lower()

            for part
            in raw_cookie.split(";")
        ]

        attributes = (
            parts[1:]
            if len(parts) > 1
            else []
        )

        has_secure = any(
            attribute == "secure"
            for attribute
            in attributes
        )

        has_httponly = any(
            attribute == "httponly"
            for attribute
            in attributes
        )

        has_samesite = any(
            attribute.startswith(
                "samesite="
            )
            for attribute
            in attributes
        )

        if not has_secure:
            insecure_cookie += 1

        if not has_httponly:
            missing_httponly += 1

        if not has_samesite:
            missing_samesite += 1


    if insecure_cookie:

        findings.append({
            "type":
                "COOKIE",

            "severity":
                "medium",

            "status":
                "detected",

            "message":
                f"{insecure_cookie} cookie(s) missing Secure flag."
        })


    if missing_httponly:

        findings.append({
            "type":
                "COOKIE",

            "severity":
                "medium",

            "status":
                "detected",

            "message":
                f"{missing_httponly} cookie(s) missing HttpOnly flag."
        })


    if missing_samesite:

        findings.append({
            "type":
                "COOKIE",

            "severity":
                "low",

            "status":
                "detected",

            "message":
                f"{missing_samesite} cookie(s) missing SameSite attribute."
        })


    # --------------------------------------------------------
    # Mixed content
    # --------------------------------------------------------

    mixed_resources = []

    if is_https:

        mixed_resources = re.findall(
            r'(?:src|href)\s*=\s*["\']http://[^"\']+["\']',
            html,
            re.IGNORECASE
        )


    if mixed_resources:

        findings.append({
            "type":
                "MIXED_CONTENT",

            "severity":
                "high",

            "status":
                "detected",

            "message":
                f"{len(mixed_resources)} insecure HTTP resource(s) referenced by an HTTPS page."
        })


    # --------------------------------------------------------
    # Forms
    # --------------------------------------------------------

    form_blocks = re.findall(
        r'<form\b[^>]*>.*?</form>',
        html,
        re.IGNORECASE
        | re.DOTALL
    )

    # Also count forms where malformed HTML prevents
    # matching the full closing form.
    opening_forms = re.findall(
        r'<form\b[^>]*>',
        html,
        re.IGNORECASE
    )

    number_of_forms = len(
        opening_forms
    )

    password_fields = len(
        re.findall(
            r'<input[^>]+type\s*=\s*["\']?password',
            html,
            re.IGNORECASE
        )
    )

    file_fields = len(
        re.findall(
            r'<input[^>]+type\s*=\s*["\']?file',
            html,
            re.IGNORECASE
        )
    )


    csrf_missing = False
    unsafe_upload = False


    for form_html in form_blocks:

        opening_match = re.search(
            r'<form\b([^>]*)>',
            form_html,
            re.IGNORECASE
        )

        opening_tag = (
            opening_match.group(1)
            if opening_match
            else ""
        )

        method_match = re.search(
            r'method\s*=\s*["\']?([^"\'\s>]+)',
            opening_tag,
            re.IGNORECASE
        )

        method = (
            method_match.group(1).upper()
            if method_match
            else "GET"
        )


        action_match = re.search(
            r'action\s*=\s*["\']([^"\']*)',
            opening_tag,
            re.IGNORECASE
        )

        action = (
            action_match.group(1)
            if action_match
            else ""
        )


        enctype_match = re.search(
            r'enctype\s*=\s*["\']([^"\']+)',
            opening_tag,
            re.IGNORECASE
        )

        enctype = (
            enctype_match.group(1).lower()
            if enctype_match
            else ""
        )


        form_has_password = bool(
            re.search(
                r'type\s*=\s*["\']?password',
                form_html,
                re.IGNORECASE
            )
        )

        form_has_file = bool(
            re.search(
                r'type\s*=\s*["\']?file',
                form_html,
                re.IGNORECASE
            )
        )


        field_names = re.findall(
            r'name\s*=\s*["\']([^"\']+)',
            form_html,
            re.IGNORECASE
        )


        has_csrf_token = any(
            re.search(
                r'csrf|token|nonce|authenticity',
                field_name,
                re.IGNORECASE
            )

            for field_name
            in field_names
        )


        sensitive_form = (
            method == "POST"

            or form_has_password

            or form_has_file
        )


        if (
            sensitive_form
            and not has_csrf_token
        ):
            csrf_missing = True


        if (
            form_has_file
            and "multipart/form-data"
            not in enctype
        ):
            unsafe_upload = True


        if (
            is_https
            and action.lower().startswith(
                "http://"
            )
        ):

            findings.append({
                "type":
                    "FORM",

                "severity":
                    "high",

                "status":
                    "detected",

                "message":
                    "Form on an HTTPS page submits data over HTTP."
            })


    if (
        password_fields > 0
        and not is_https
    ):

        findings.append({
            "type":
                "FORM",

            "severity":
                "high",

            "status":
                "detected",

            "message":
                "Password field detected on a non-HTTPS page."
        })


    if csrf_missing:

        findings.append({
            "type":
                "CSRF",

            "severity":
                "medium",

            "status":
                "potential",

            "message":
                "Sensitive form found without an obvious CSRF token."
        })


    if unsafe_upload:

        findings.append({
            "type":
                "FILE_UPLOAD",

            "severity":
                "medium",

            "status":
                "potential",

            "message":
                "File upload form does not appear to use multipart/form-data."
        })


    # --------------------------------------------------------
    # Script analysis / DOM XSS indicator
    # --------------------------------------------------------

    external_scripts = re.findall(
        r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']',
        html,
        re.IGNORECASE
    )


    inline_script_blocks = re.findall(
        r'<script(?![^>]*src)[^>]*>(.*?)</script>',
        html,
        re.IGNORECASE
        | re.DOTALL
    )


    inline_script_text = (
        "\n".join(
            inline_script_blocks
        ).lower()
    )


    dom_sources = [
        "location.hash",
        "location.search",
        "document.url",
        "document.location",
        "window.name",
    ]


    dom_sinks = [
        ".innerhtml",
        ".outerhtml",
        "document.write(",
        "eval(",
        "insertadjacenthtml(",
    ]


    source_found = any(
        source in inline_script_text
        for source
        in dom_sources
    )


    sink_found = any(
        sink in inline_script_text
        for sink
        in dom_sinks
    )


    potential_dom_xss = (
        source_found
        and sink_found
    )


    if potential_dom_xss:

        findings.append({
            "type":
                "DOM_XSS",

            "severity":
                "medium",

            "status":
                "potential",

            "message":
                "Potential DOM XSS source/sink pattern detected in page JavaScript."
        })


    # --------------------------------------------------------
    # Other informational surfaces
    # --------------------------------------------------------

    api_surface = bool(
        re.search(
            r'["\'][^"\']*/api(?:/|\?|["\'])',
            html,
            re.IGNORECASE
        )
    )


    captcha_surface = bool(
        re.search(
            r'recaptcha|g-recaptcha|captcha',
            html,
            re.IGNORECASE
        )
    )


    technologies = (
        _detect_technologies(
            html,
            headers
        )
    )


    # LOGIN IS INFORMATIONAL ONLY.
    login_surface = (
        password_fields > 0
    )


    weak_session = (
        insecure_cookie > 0
        or missing_httponly > 0
    )


    return {
        "status_code":
            response.status_code,

        "headers":
            headers,

        "is_https":
            is_https,

        "num_forms":
            number_of_forms,

        "password_fields":
            password_fields,

        "file_fields":
            file_fields,

        "external_scripts":
            len(external_scripts),

        "inline_scripts":
            len(inline_script_blocks),

        "mixed_content_count":
            len(mixed_resources),

        "technologies":
            technologies,

        "indicators": {
            "csrfMissingToken":
                csrf_missing,

            "unsafeUpload":
                unsafe_upload,

            "weakSession":
                weak_session,

            "weakCsp":
                weak_csp,

            "domXss":
                potential_dom_xss,

            "apiSurface":
                api_surface,

            "captchaSurface":
                captcha_surface,
        },

        "surfaces": {
            "loginSurface":
                login_surface,

            "fileUploadSurface":
                file_fields > 0,

            "apiSurface":
                api_surface,

            "captchaSurface":
                captcha_surface,
        },

        "findings":
            findings,
    }


# ============================================================
# Active reflected-input check
# ============================================================

def _check_reflected_param(
    session,
    base_url,
    parameter
):

    try:
        test_url = _replace_parameter(
            base_url,
            parameter,
            SAFE_XSS_MARKER
        )

        response = session.get(
            test_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        text = (
            response.text
            or ""
        )

        return {
            "param":
                parameter,

            "reflected":
                "vulnscan-probe-12345"
                in text,

            "reflectedUnescaped":
                SAFE_XSS_MARKER
                in text,
        }

    except requests.RequestException as error:

        return {
            "param":
                parameter,

            "reflected":
                False,

            "reflectedUnescaped":
                False,

            "error":
                str(error),
        }


# ============================================================
# Active SQL error indicator
# ============================================================

def _check_sql_error(
    session,
    base_url,
    parameter,
    original_value
):

    try:
        test_url = _replace_parameter(
            base_url,
            parameter,
            f"{original_value}'"
        )

        response = session.get(
            test_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )

        text = (
            response.text
            or ""
        ).lower()

        matched = next(
            (
                signature

                for signature
                in SQL_ERROR_SIGNATURES

                if signature in text
            ),
            None
        )

        return {
            "param":
                parameter,

            "sqlErrorDetected":
                bool(matched),

            "signature":
                matched,
        }

    except requests.RequestException as error:

        return {
            "param":
                parameter,

            "sqlErrorDetected":
                False,

            "signature":
                None,

            "error":
                str(error),
        }


# ============================================================
# Blind SQL response-difference indicator
# ============================================================

def _check_blind_sql(
    session,
    base_url,
    parameter,
    original_value
):

    try:
        baseline_url = (
            base_url
        )

        true_url = _replace_parameter(
            base_url,
            parameter,
            f"{original_value}' AND '1'='1"
        )

        false_url = _replace_parameter(
            base_url,
            parameter,
            f"{original_value}' AND '1'='2"
        )


        baseline_response = session.get(
            baseline_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )


        true_response = session.get(
            true_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )


        false_response = session.get(
            false_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )


        baseline_text = (
            baseline_response.text
            or ""
        )

        true_text = (
            true_response.text
            or ""
        )

        false_text = (
            false_response.text
            or ""
        )


        true_difference = abs(
            len(baseline_text)
            - len(true_text)
        )


        false_difference = abs(
            len(baseline_text)
            - len(false_text)
        )


        potential = (
            false_difference > 50
            and true_difference
            < false_difference * 0.5
        )


        return {
            "param":
                parameter,

            "potentialBlindSql":
                potential,

            "baselineLength":
                len(baseline_text),

            "trueLength":
                len(true_text),

            "falseLength":
                len(false_text),
        }

    except requests.RequestException as error:

        return {
            "param":
                parameter,

            "potentialBlindSql":
                False,

            "error":
                str(error),
        }


# ============================================================
# Open redirect indicator
# ============================================================

def _check_open_redirect(
    session,
    base_url
):

    findings = []

    parts = urlsplit(
        base_url
    )

    query = dict(
        parse_qsl(
            parts.query,
            keep_blank_values=True
        )
    )


    for parameter in REDIRECT_PARAMETERS:

        if parameter not in query:
            continue

        try:
            test_url = _replace_parameter(
                base_url,
                parameter,
                "https://example.invalid/vulnscan-test"
            )

            response = session.get(
                test_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )

            location = (
                response.headers.get(
                    "Location",
                    ""
                )
            )


            if (
                300
                <= response.status_code
                < 400

                and "example.invalid"
                in location
            ):

                findings.append({
                    "param":
                        parameter,

                    "potentialOpenRedirect":
                        True,
                })

        except requests.RequestException:
            continue


    return findings


# ============================================================
# Active scan
# ============================================================

def active_scan(
    url: str,
    max_params: int = 5
) -> dict:
    """
    Perform local-lab active checks.

    No brute-force/password guessing is performed.
    """

    _assert_local_lab(
        url
    )

    findings = []

    informational = []

    session = _session()

    parts = urlsplit(
        url
    )

    origin = (
        f"{parts.scheme}://"
        f"{parts.netloc}"
    )


    # --------------------------------------------------------
    # Surface discovery
    # --------------------------------------------------------

    try:
        page_response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )

        page_html = (
            page_response.text
            or ""
        )

    except requests.RequestException:
        page_html = ""


    login_surface = bool(
        re.search(
            r'type\s*=\s*["\']?password',
            page_html,
            re.IGNORECASE
        )
    )


    upload_surface = bool(
        re.search(
            r'type\s*=\s*["\']?file',
            page_html,
            re.IGNORECASE
        )
    )


    # IMPORTANT:
    # Login form is informational only.
    if login_surface:

        informational.append({
            "type":
                "LOGIN_SURFACE",

            "message":
                "Login/password form detected. This does not prove a brute-force vulnerability."
        })


    if upload_surface:

        informational.append({
            "type":
                "FILE_UPLOAD_SURFACE",

            "message":
                "File upload input detected. Upload functionality alone is not a vulnerability."
        })


    # --------------------------------------------------------
    # Common directories
    # --------------------------------------------------------

    directory_results = []


    for directory in COMMON_DIRECTORIES:

        try:
            response = session.get(
                origin + directory,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )

            directory_results.append({
                "path":
                    directory,

                "status":
                    response.status_code,

                "exists":
                    response.status_code
                    == 200,
            })

        except requests.RequestException as error:

            directory_results.append({
                "path":
                    directory,

                "exists":
                    False,

                "error":
                    str(error),
            })


    exposed = [
        result

        for result
        in directory_results

        if result.get(
            "exists"
        )
    ]


    if exposed:

        findings.append({
            "type":
                "EXPOSED_PATH",

            "severity":
                "medium",

            "status":
                "potential",

            "message":
                "Potentially exposed path(s): "
                + ", ".join(
                    result["path"]

                    for result
                    in exposed
                )
        })


    # --------------------------------------------------------
    # Query parameters
    # --------------------------------------------------------

    query_parameters = dict(
        parse_qsl(
            parts.query,
            keep_blank_values=True
        )
    )


    parameter_names = list(
        query_parameters.keys()
    )[:max_params]


    command_input_surface = any(
        parameter.lower()
        in COMMAND_PARAMETER_NAMES

        for parameter
        in parameter_names
    )


    file_path_input_surface = any(
        parameter.lower()
        in FILE_PARAMETER_NAMES

        for parameter
        in parameter_names
    )


    if command_input_surface:

        informational.append({
            "type":
                "COMMAND_INPUT_SURFACE",

            "message":
                "Command-style parameter detected. No command injection vulnerability was confirmed."
        })


    if file_path_input_surface:

        informational.append({
            "type":
                "FILE_PATH_SURFACE",

            "message":
                "File/path-style parameter detected. No file inclusion vulnerability was confirmed."
        })


    # --------------------------------------------------------
    # Reflected XSS / SQL indicators
    # --------------------------------------------------------

    xss_results = []

    sql_results = []

    blind_sql_results = []


    for parameter in parameter_names:

        original_value = (
            query_parameters.get(
                parameter
            )
            or "1"
        )


        xss_results.append(
            _check_reflected_param(
                session,
                url,
                parameter
            )
        )


        sql_results.append(
            _check_sql_error(
                session,
                url,
                parameter,
                original_value
            )
        )


        blind_sql_results.append(
            _check_blind_sql(
                session,
                url,
                parameter,
                original_value
            )
        )


    reflected_hits = [
        result

        for result
        in xss_results

        if result.get(
            "reflectedUnescaped"
        )
    ]


    if reflected_hits:

        findings.append({
            "type":
                "XSS",

            "severity":
                "high",

            "status":
                "potential",

            "message":
                "Unescaped reflection detected for parameter(s): "
                + ", ".join(
                    result["param"]

                    for result
                    in reflected_hits
                )
        })


    sql_hits = [
        result

        for result
        in sql_results

        if result.get(
            "sqlErrorDetected"
        )
    ]


    if sql_hits:

        findings.append({
            "type":
                "SQLI",

            "severity":
                "critical",

            "status":
                "potential",

            "message":
                "Database error indicator detected for parameter(s): "
                + ", ".join(
                    result["param"]

                    for result
                    in sql_hits
                )
        })


    blind_hits = [
        result

        for result
        in blind_sql_results

        if result.get(
            "potentialBlindSql"
        )
    ]


    if blind_hits:

        findings.append({
            "type":
                "BLIND_SQLI",

            "severity":
                "high",

            "status":
                "potential",

            "message":
                "Possible boolean response difference detected for parameter(s): "
                + ", ".join(
                    result["param"]

                    for result
                    in blind_hits
                )
        })


    # --------------------------------------------------------
    # Open redirect
    # --------------------------------------------------------

    redirect_results = (
        _check_open_redirect(
            session,
            url
        )
    )


    if redirect_results:

        findings.append({
            "type":
                "OPEN_REDIRECT",

            "severity":
                "medium",

            "status":
                "potential",

            "message":
                "Potential open redirect detected through parameter(s): "
                + ", ".join(
                    result["param"]

                    for result
                    in redirect_results
                )
        })


    return {
        "directory_results":
            directory_results,

        "xss_results":
            xss_results,

        "sql_results":
            sql_results,

        "blind_sql_results":
            blind_sql_results,

        "redirect_results":
            redirect_results,

        "surfaces": {
            "loginSurface":
                login_surface,

            "fileUploadSurface":
                upload_surface,

            "commandInputSurface":
                command_input_surface,

            "filePathInputSurface":
                file_path_input_surface,
        },

        "informational":
            informational,

        "indicators": {
            "reflectedXss":
                bool(
                    reflected_hits
                ),

            "sqlError":
                bool(
                    sql_hits
                ),

            "blindSqli":
                bool(
                    blind_hits
                ),

            "openRedirect":
                bool(
                    redirect_results
                ),
        },

        "findings":
            findings,
    }