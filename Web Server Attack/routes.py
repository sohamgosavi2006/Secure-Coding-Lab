"""
WebShield Lab — Web Server Attack and Defense Simulator (Project 3)
Flask Blueprint: web_server_attack_bp

Demonstrates:
1. Directory Listing Misconfiguration (CWE-548): Exposed browsable directory structure.
2. Sensitive File in Public Web Root (CWE-552 / CWE-200): Fictional config file exposed.
3. Secure Countermeasures:
   - Disabling directory indexing (403 Forbidden).
   - Moving private files outside the public web root.
   - Strict allowlisting of public resources.
   - Defensive security headers (X-Content-Type-Options, X-Frame-Options).
"""

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, request, jsonify, make_response, send_from_directory, render_template_string

ROOT_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = ROOT_DIR / "fixtures"
PUBLIC_VULN_DIR = FIXTURES_DIR / "public_vulnerable"
PUBLIC_SEC_DIR = FIXTURES_DIR / "public_secure"
PRIVATE_STORAGE_DIR = FIXTURES_DIR / "private_storage"

# -----------------------------------------------------------------------------
# Blueprint & Global Setup
# -----------------------------------------------------------------------------

web_server_attack_bp = Blueprint(
    "web_server_attack",
    __name__,
    url_prefix="/web-server-attack"
)

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def get_directory_entries(directory: Path):
    """Retrieve metadata for files inside a designated fixture directory."""
    entries = []
    if not directory.exists():
        return entries
    
    for item in sorted(directory.iterdir()):
        if item.is_file() and not item.name.startswith("."):
            stat = item.stat()
            entries.append({
                "name": item.name,
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "is_sensitive": item.name in {"demo-config.txt", "backup-demo.txt"},
                "content_type": "text/html" if item.suffix == ".html" else "text/plain"
            })
    return entries

def is_safe_path(base_dir: Path, requested_path: str) -> bool:
    """Validate that requested path resolves strictly inside base_dir without traversal."""
    try:
        resolved_base = base_dir.resolve()
        target = (base_dir / requested_path).resolve()
        return target == resolved_base or resolved_base in target.parents
    except Exception:
        return False

# -----------------------------------------------------------------------------
# Module Status and File Tree Information
# -----------------------------------------------------------------------------
@web_server_attack_bp.route("/api/status", methods=["GET"])
def module_status():
    """Return status and file hierarchy of the training environment."""
    vuln_files = get_directory_entries(PUBLIC_VULN_DIR)
    sec_files = get_directory_entries(PUBLIC_SEC_DIR)
    private_files = get_directory_entries(PRIVATE_STORAGE_DIR)

    return jsonify({
        "status": "active",
        "module_name": "WebShield Lab — Web Server Attack & Defense",
        "description": "Directory Listing and Sensitive File Exposure Simulator",
        "public_vulnerable_root": str(PUBLIC_VULN_DIR),
        "public_secure_root": str(PUBLIC_SEC_DIR),
        "private_storage_root": str(PRIVATE_STORAGE_DIR),
        "vulnerable_directory_files": vuln_files,
        "secure_directory_files": sec_files,
        "private_storage_files": private_files,
        "allowed_public_files": sorted(list(ALLOWED_PUBLIC_FILES))
    })

# -----------------------------------------------------------------------------
# Vulnerable Implementation: Directory Listing & Public Web Root Exposure
# -----------------------------------------------------------------------------
@web_server_attack_bp.route("/vulnerable/browse", methods=["GET"])
@web_server_attack_bp.route("/vulnerable/", methods=["GET"])
def vulnerable_browse():
    """
    VULNERABLE HANDLER: Directory Listing Enabled (CWE-548).
    Simulates Apache 'Options +Indexes' or Nginx 'autoindex on;'.
    Lists all files in the public directory, exposing filenames and metadata.
    """
    entries = get_directory_entries(PUBLIC_VULN_DIR)

    # Return JSON if requested programmatically
    if request.args.get("format") == "json" or request.headers.get("Accept") == "application/json":
        return jsonify({
            "status": "vulnerable_directory_listing_enabled",
            "directory": "/vulnerable/files/",
            "total_files": len(entries),
            "files": entries,
            "security_note": "CRITICAL: Directory indexing is enabled. All files in web root are exposed."
        }), 200

    # Render classic Apache/Nginx-style directory listing HTML
    html_template = """<!DOCTYPE html>
<html>
<head>
    <title>Index of /vulnerable/files/</title>
    <style>
        body { font-family: monospace; padding: 24px; background: #fff; color: #111; }
        h1 { border-bottom: 1px solid #ccc; padding-bottom: 8px; font-size: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }
        th, td { text-align: left; padding: 6px 12px; }
        th { border-bottom: 1px solid #444; }
        tr:nth-child(even) { background: #f9f9f9; }
        a { color: #0000ee; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .tag-exposed { color: #b91c1c; font-weight: bold; }
        .footer { margin-top: 24px; padding-top: 8px; border-top: 1px solid #ccc; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <h1>Index of /vulnerable/files/</h1>
    <table>
        <tr>
            <th>Name</th>
            <th>Last modified</th>
            <th>Size</th>
            <th>Type</th>
            <th>Security Classification</th>
        </tr>
        {% for file in files %}
        <tr>
            <td><a href="/web-server-attack/vulnerable/files/{{ file.name }}">{{ file.name }}</a></td>
            <td>{{ file.modified }}</td>
            <td>{{ file.size_bytes }} B</td>
            <td>{{ file.content_type }}</td>
            <td>
                {% if file.is_sensitive %}
                <span class="tag-exposed">⚠️ SENSITIVE EXPOSED</span>
                {% else %}
                <span>Public Document</span>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
    <div class="footer">
        Apache/2.4.52 (Unix) Server at 127.0.0.1 Port 5050 [Simulated Misconfiguration: Options +Indexes]
    </div>
</body>
</html>"""
    resp = make_response(render_template_string(html_template, files=entries))
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Server"] = "Apache/2.4.52 (Unix) Simulated"
    return resp, 200

@web_server_attack_bp.route("/vulnerable/files/<path:filename>", methods=["GET"])
def vulnerable_serve_file(filename: str):
    """
    VULNERABLE HANDLER: Direct File Serving from Public Web Root (CWE-552).
    Serves any file placed inside the web root without access restriction.
    Sensitive configuration files (e.g. demo-config.txt) are publicly retrievable.
    """
    # Defensive containment: prevent path traversal (reject ../)
    if ".." in filename or filename.startswith("/") or not is_safe_path(PUBLIC_VULN_DIR, filename):
        resp = make_response(jsonify({
            "error": "Bad Request: Path traversal rejected for lab containment safety.",
            "status_code": 400
        }), 400)
        resp.headers["Content-Type"] = "application/json"
        return resp

    target_file = (PUBLIC_VULN_DIR / filename).resolve()
    if not target_file.is_file():
        resp = make_response(jsonify({
            "error": f"File '{filename}' not found in public web root.",
            "status_code": 404
        }), 404)
        resp.headers["Content-Type"] = "application/json"
        return resp

    content_type = "text/html; charset=utf-8" if target_file.suffix == ".html" else "text/plain; charset=utf-8"
    content = target_file.read_text(
        encoding="utf-8",
        errors="replace"
    )

    resp = make_response(content, 200)
    resp.headers["Content-Type"] = content_type
    resp.headers["Server"] = "Apache/2.4.52 (Unix) Simulated"
    resp.headers["X-Lab-Exposure"] = "Vulnerable: File served directly from public web root"
    return resp

# -----------------------------------------------------------------------------
# Secure Implementation: Hardened Directory & Allowlisted Resource Serving
# -----------------------------------------------------------------------------
# Explicit allowlist: Only approved public assets can be served to visitors
ALLOWED_PUBLIC_FILES = {
    "index.html",
    "about.html"
}

@web_server_attack_bp.route("/secure/", methods=["GET"])
@web_server_attack_bp.route("/secure", methods=["GET"])
def secure_index():
    """
    SECURE HOMEPAGE: Serves approved index.html when root path is requested.
    """
    return secure_serve_file("index.html")

@web_server_attack_bp.route("/secure/browse", methods=["GET"])
def secure_browse():
    """
    SECURE HANDLER: Directory Indexing Disabled (Mitigation for CWE-548).
    Simulates Apache 'Options -Indexes' or Nginx 'autoindex off;'.
    Refuses directory browsing with an explicit HTTP 403 Forbidden status.
    """
    if request.args.get("format") == "json" or request.headers.get("Accept") == "application/json":
        resp = make_response(jsonify({
            "status": "directory_indexing_disabled",
            "status_code": 403,
            "error": "Forbidden: Directory browsing is strictly prohibited on this server.",
            "countermeasure": "Apache: Options -Indexes | Nginx: autoindex off;"
        }), 403)
        resp.headers["Content-Type"] = "application/json"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    html_error = """<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; background: #fff; color: #1e293b; }
        .box { max-width: 600px; border-left: 4px solid #b91c1c; padding: 16px 24px; background: #fef2f2; border-radius: 4px; }
        h1 { color: #991b1b; margin-top: 0; font-size: 22px; }
        p { color: #475569; font-size: 14px; line-height: 1.5; }
        code { background: #fee2e2; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
        .footer { margin-top: 24px; font-size: 12px; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="box">
        <h1>403 Forbidden — Directory Browsing Prohibited</h1>
        <p>You do not have permission to access or view the directory listing for this path.</p>
        <p><strong>Security Policy:</strong> Directory indexing is disabled (<code>Options -Indexes</code> / <code>autoindex off</code>). File structure cannot be browsed.</p>
    </div>
    <div class="footer">WebShield-Hardened/2.0 Server at 127.0.0.1 Port 5050</div>
</body>
</html>"""
    resp = make_response(html_error, 403)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Server"] = "WebShield-Hardened/2.0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

@web_server_attack_bp.route("/secure/files/<path:filename>", methods=["GET"])
def secure_serve_file(filename: str):
    """
    SECURE HANDLER: Allowlisted Public File Serving (Mitigation for CWE-552).
    Countermeasures applied:
    1. Confidential configuration files stored outside public web root in private_storage/.
    2. Strict Allowlist: Only explicitly approved public files (index.html, about.html) are served.
    3. Requests for disallowed or confidential files are rejected with 403 Forbidden or 404 Not Found.
    4. Defensive HTTP response headers set.
    """
    # Defensive containment: prevent path traversal
    if ".." in filename or filename.startswith("/") or not is_safe_path(PUBLIC_SEC_DIR, filename):
        resp = make_response(jsonify({
            "error": "Bad Request: Path traversal rejected.",
            "status_code": 400
        }), 400)
        resp.headers["Content-Type"] = "application/json"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    # Step 1: Strict Allowlist Check
    if filename not in ALLOWED_PUBLIC_FILES:
        # Check if the requested file was a sensitive file attempting to be retrieved
        if filename in {"demo-config.txt", "backup-demo.txt"}:
            resp = make_response(jsonify({
                "error": f"Access Denied: Resource '{filename}' is confidential and segregated outside the public web root.",
                "status_code": 403,
                "reason": "Defense-in-depth: Sensitive configuration files are stored in private storage and barred from public routing.",
                "countermeasure": "File segregated to private_storage/ and rejected by allowlist."
            }), 403)
        else:
            resp = make_response(jsonify({
                "error": f"Resource '{filename}' not found or not in the public allowlist.",
                "status_code": 404,
                "reason": "Only explicitly allowlisted public assets are served."
            }), 404)
        
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Server"] = "WebShield-Hardened/2.0"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    # Step 2: Serve allowlisted file from public_secure directory
    target_file = (PUBLIC_SEC_DIR / filename).resolve()
    if not target_file.is_file():
        resp = make_response(jsonify({
            "error": f"Allowlisted file '{filename}' does not exist on disk.",
            "status_code": 404
        }), 404)
        resp.headers["Content-Type"] = "application/json"
        return resp

    content = target_file.read_text(encoding="utf-8", errors="replace")
    content_type = "text/html; charset=utf-8" if target_file.suffix == ".html" else "text/plain; charset=utf-8"

    resp = make_response(content, 200)
    resp.headers["Content-Type"] = content_type
    resp.headers["Server"] = "WebShield-Hardened/2.0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Lab-Protection"] = "Hardened: File verified against strict public allowlist"
    return resp

# -----------------------------------------------------------------------------
# Source Code Inspection API (Loads Real Code with Line Numbers & Highlights)
# -----------------------------------------------------------------------------
ALLOWED_SOURCE_TARGETS = {
    "vulnerable": {
        "function": "vulnerable_browse and vulnerable_serve_file",
        "file_path": "Web Server Attack/routes.py",
        "start_marker": "def vulnerable_browse():",
        "end_marker": "# Secure Implementation",
        "explanation": "The vulnerable handlers enable directory listing and serve arbitrary files from the public folder without checking whether they are confidential."
    },
    "secure": {
        "function": "secure_browse and secure_serve_file",
        "file_path": "Web Server Attack/routes.py",
        "start_marker": "ALLOWED_PUBLIC_FILES = {",
        "end_marker": "# Source Code Inspection API",
        "explanation": "The secure handler refuses directory browsing with 403 Forbidden, restricts served resources to an explicit ALLOWED_PUBLIC_FILES set, and isolates sensitive files outside the web root."
    }
}

@web_server_attack_bp.route("/api/source", methods=["GET"])
def get_source_code():
    """
    Examine the genuine source code responsible for the behavior.
    Uses strict allowlisting of permitted targets to prevent arbitrary file reading.
    """
    target = request.args.get("target", "vulnerable")
    if target not in ALLOWED_SOURCE_TARGETS:
        return jsonify({"error": "Invalid target specified. Permitted: vulnerable, secure"}), 400

    cfg = ALLOWED_SOURCE_TARGETS[target]
    routes_file = ROOT_DIR / "routes.py"
    if not routes_file.exists():
        return jsonify({"error": "Source file not found on disk"}), 404

    lines = routes_file.read_text(encoding="utf-8").splitlines()
    
    # Locate section
    start_idx = 0
    end_idx = len(lines)
    for i, line in enumerate(lines):
        if cfg["start_marker"] in line:
            start_idx = max(0, i - 1 if target == "secure" else i - 5)
            break
    
    for i in range(start_idx + 3, len(lines)):
        if cfg["end_marker"] in lines[i]:
            end_idx = i - 1
            break

    extracted_lines = lines[start_idx:end_idx]
    
    # Build line number mapping & classifications
    code_with_numbers = []
    in_read_text_call = False
    in_html_loop = False
    in_vuln_path_defense = False
    in_allowlist_def = False
    in_allowlist_check_call = False

    for rel_idx, line in enumerate(extracted_lines):
        abs_line_num = start_idx + rel_idx + 1
        is_highlight = False
        highlight_type = None
        finding_id = None
        annotation = None

        if target == "vulnerable":
            # 1. Directory listing vulnerability (RED)
            if "entries = get_directory_entries(PUBLIC_VULN_DIR)" in line:
                is_highlight = True
                highlight_type = "vulnerable"
                finding_id = "vuln_dir_listing"
                annotation = "Root cause: The vulnerable handler exposes directory entries to visitors. This can reveal filenames of resources that should not be discoverable."
            elif "{% for file in files %}" in line:
                is_highlight = True
                highlight_type = "vulnerable"
                finding_id = "vuln_dir_listing"
                in_html_loop = True
                annotation = "Root cause: The vulnerable handler renders directory links, disclosing sensitive filenames to visitors."
            elif in_html_loop:
                is_highlight = True
                highlight_type = "vulnerable"
                finding_id = "vuln_dir_listing"
                annotation = "Root cause: The vulnerable handler renders directory links, disclosing sensitive filenames to visitors."
                if "{% endfor %}" in line:
                    in_html_loop = False

            # 2. Defensive path check (NEUTRAL BLUE) - Valid defense, not a vulnerability!
            elif 'if ".." in filename or filename.startswith("/") or not is_safe_path(PUBLIC_VULN_DIR, filename):' in line:
                is_highlight = True
                highlight_type = "defense_neutral"
                finding_id = "defense_path_check"
                in_vuln_path_defense = True
                annotation = "Path validation present: Blocks path traversal, but does not prevent exposure of sensitive files legitimately stored in the public directory."
            elif in_vuln_path_defense:
                is_highlight = True
                highlight_type = "defense_neutral"
                finding_id = "defense_path_check"
                annotation = "Path validation present: Blocks path traversal, but does not prevent exposure of sensitive files legitimately stored in the public directory."
                if "return resp" in line:
                    in_vuln_path_defense = False

            # 3. Direct file exposure vulnerability (RED)
            elif "target_file = (PUBLIC_VULN_DIR / filename).resolve()" in line:
                is_highlight = True
                highlight_type = "vulnerable"
                finding_id = "vuln_file_exposure"
                annotation = "Root cause: The handler reads and returns requested files from the public directory without restricting access to explicitly approved public resources."
            elif "target_file.read_text(" in line:
                is_highlight = True
                highlight_type = "vulnerable"
                finding_id = "vuln_file_exposure"
                in_read_text_call = True
                annotation = "Root cause: Reads arbitrary file content without enforcing a strict public allowlist."
            elif in_read_text_call:
                is_highlight = True
                highlight_type = "vulnerable"
                finding_id = "vuln_file_exposure"
                annotation = "Root cause: Reads arbitrary file content without enforcing a strict public allowlist."
                if ")" in line:
                    in_read_text_call = False
            elif "resp = make_response(content, 200)" in line and rel_idx > 80:
                is_highlight = True
                highlight_type = "vulnerable"
                finding_id = "vuln_file_exposure"
                annotation = "Root cause: Serves requested file with HTTP 200 OK without verifying authorization or allowlisting."

        elif target == "secure":
            # 1. Strict public allowlist definition (GREEN)
            if "ALLOWED_PUBLIC_FILES = {" in line:
                is_highlight = True
                highlight_type = "secure"
                finding_id = "sec_allowlist_def"
                in_allowlist_def = True
                annotation = "Protection: Only explicitly approved public files are eligible to be served."
            elif in_allowlist_def:
                is_highlight = True
                highlight_type = "secure"
                finding_id = "sec_allowlist_def"
                annotation = "Protection: Only explicitly approved public files are eligible to be served."
                if "}" in line:
                    in_allowlist_def = False

            # 2. Directory browsing denial (GREEN)
            elif any(k in line for k in [
                'status_code": 403',
                'make_response(html_error, 403)',
                '"countermeasure": "Apache: Options -Indexes | Nginx: autoindex off;"'
            ]) and rel_idx < 60:
                is_highlight = True
                highlight_type = "secure"
                finding_id = "sec_dir_browse_denied"
                annotation = "Protection: Directory browsing is denied. The handler does not enumerate or render the directory contents."

            # 3. Safe path containment (GREEN)
            elif any(k in line for k in [
                'if ".." in filename or filename.startswith("/") or not is_safe_path(PUBLIC_SEC_DIR, filename):',
                'target_file = (PUBLIC_SEC_DIR / filename).resolve()'
            ]):
                is_highlight = True
                highlight_type = "secure"
                finding_id = "sec_path_containment"
                annotation = "Protection: The requested file is restricted to the intended public directory, helping prevent path traversal."

            # 4. Strict allowlist check and rejection (GREEN)
            elif "if filename not in ALLOWED_PUBLIC_FILES:" in line:
                is_highlight = True
                highlight_type = "secure"
                finding_id = "sec_allowlist_check"
                in_allowlist_check_call = True
                annotation = "Protection: Rejects filenames not in the allowlist. Knowing the name of a private file does not grant access."
            elif in_allowlist_check_call:
                is_highlight = True
                highlight_type = "secure"
                finding_id = "sec_allowlist_check"
                annotation = "Protection: Rejects filenames not in the allowlist. Knowing the name of a private file does not grant access."
                if "return resp" in line:
                    in_allowlist_check_call = False

            # 5. Public-file serving after verification (GREEN)
            elif 'resp = make_response(content, 200)' in line and rel_idx > 50:
                is_highlight = True
                highlight_type = "secure"
                finding_id = "sec_safe_serve"
                annotation = "Protection: Reading and returning a file is safe here because the resource has passed allowlist and path checks."

        code_with_numbers.append({
            "line_number": abs_line_num,
            "code": line,
            "highlight": is_highlight,
            "highlight_type": highlight_type,
            "finding_id": finding_id,
            "annotation": annotation
        })

    # Summary findings list for educational navigation
    findings_summary = []
    if target == "vulnerable":
        findings_summary = [
            {
                "id": "vuln_dir_listing",
                "title": "Directory Listing Vulnerability",
                "cwe": "CWE-548",
                "type": "vulnerable",
                "badge": "VULNERABILITY",
                "explanation": "Root cause: The vulnerable handler exposes directory entries to visitors. This can reveal filenames of resources that should not be discoverable."
            },
            {
                "id": "vuln_file_exposure",
                "title": "Direct-File Exposure Vulnerability",
                "cwe": "CWE-552",
                "type": "vulnerable",
                "badge": "VULNERABILITY",
                "explanation": "Root cause: The handler reads and returns requested files from the public directory without restricting access to explicitly approved public resources. Consequently, sensitive files stored in that directory may be exposed."
            },
            {
                "id": "defense_path_check",
                "title": "Path Validation Present",
                "cwe": "DEFENSE-IN-DEPTH",
                "type": "defense_neutral",
                "badge": "PATH DEFENSE",
                "explanation": "Path validation present: Path traversal is blocked, but this check alone does not prevent exposure of a sensitive file that is legitimately located inside the public directory."
            }
        ]
    elif target == "secure":
        findings_summary = [
            {
                "id": "sec_dir_browse_denied",
                "title": "Directory Browsing Denied",
                "cwe": "MITIGATION (CWE-548)",
                "type": "secure",
                "badge": "PROTECTION",
                "explanation": "Protection: Directory browsing is denied. The handler does not enumerate or render the directory contents."
            },
            {
                "id": "sec_allowlist_def",
                "title": "Strict Public-File Allowlist",
                "cwe": "MITIGATION (CWE-552)",
                "type": "secure",
                "badge": "PROTECTION",
                "explanation": "Protection: Only explicitly approved public files are eligible to be served."
            },
            {
                "id": "sec_allowlist_check",
                "title": "Allowlist Enforcement & Denial",
                "cwe": "MITIGATION (CWE-552)",
                "type": "secure",
                "badge": "PROTECTION",
                "explanation": "Protection: Rejects filenames not in the allowlist, ensuring that knowing the name of a private file does not grant access to it."
            },
            {
                "id": "sec_path_containment",
                "title": "Safe Path Containment",
                "cwe": "CONTAINMENT",
                "type": "secure",
                "badge": "PROTECTION",
                "explanation": "Protection: The requested file is restricted to the intended public directory, helping prevent path traversal."
            },
            {
                "id": "sec_safe_serve",
                "title": "Approved Public-File Serving",
                "cwe": "SECURE SERVING",
                "type": "secure",
                "badge": "PROTECTION",
                "explanation": "Protection: Reading and returning a file is safe here because the resource has passed the applicable allowlist and path checks."
            }
        ]

    return jsonify({
        "success": True,
        "target": target,
        "file_path": cfg["file_path"],
        "absolute_start_line": start_idx + 1,
        "total_lines": len(code_with_numbers),
        "code_lines": code_with_numbers,
        "raw_text": "\n".join(extracted_lines),
        "explanation": cfg["explanation"],
        "findings": findings_summary
    })

# -----------------------------------------------------------------------------
# Comparison Matrix Live Verification Test Runner API
# -----------------------------------------------------------------------------
@web_server_attack_bp.route("/api/compare-tests", methods=["GET"])
def run_comparison_tests():
    """
    Executes the standard test suite against both vulnerable and secure configurations:
    1. Request public homepage (index.html)
    2. Browse directory (/browse)
    3. Request dummy configuration (demo-config.txt)
    4. Request allowed public page (about.html)
    5. Request unknown filename (missing.txt)
    """
    from flask import current_app

    test_cases = [
        {
            "id": "test-1",
            "name": "Request Public Homepage",
            "resource": "index.html",
            "vulnerable_path": "/web-server-attack/vulnerable/files/index.html",
            "secure_path": "/web-server-attack/secure/files/index.html",
            "expected_vulnerable_status": 200,
            "expected_secure_status": 200,
            "description": "Legitimate public homepage should load successfully in both configurations."
        },
        {
            "id": "test-2",
            "name": "Browse Directory Structure",
            "resource": "Directory root (/browse)",
            "vulnerable_path": "/web-server-attack/vulnerable/browse",
            "secure_path": "/web-server-attack/secure/browse",
            "expected_vulnerable_status": 200,
            "expected_secure_status": 403,
            "description": "Vulnerable server exposes complete file list (CWE-548); secure server returns 403 Forbidden."
        },
        {
            "id": "test-3",
            "name": "Request Dummy Configuration File",
            "resource": "demo-config.txt",
            "vulnerable_path": "/web-server-attack/vulnerable/files/demo-config.txt",
            "secure_path": "/web-server-attack/secure/files/demo-config.txt",
            "expected_vulnerable_status": 200,
            "expected_secure_status": 403,  # Or 404, our secure handler returns 403 for known confidential files or 404 for missing
            "description": "Vulnerable server exposes sensitive credentials; secure server blocks access and keeps config outside web root."
        },
        {
            "id": "test-4",
            "name": "Request Allowed Public Page",
            "resource": "about.html",
            "vulnerable_path": "/web-server-attack/vulnerable/files/about.html",
            "secure_path": "/web-server-attack/secure/files/about.html",
            "expected_vulnerable_status": 200,
            "expected_secure_status": 200,
            "description": "Allowlisted public informational page loads successfully in both configurations."
        },
        {
            "id": "test-5",
            "name": "Request Unknown Resource",
            "resource": "missing-nonexistent.txt",
            "vulnerable_path": "/web-server-attack/vulnerable/files/missing-nonexistent.txt",
            "secure_path": "/web-server-attack/secure/files/missing-nonexistent.txt",
            "expected_vulnerable_status": 404,
            "expected_secure_status": 404,
            "description": "Non-existent files return a standard 404 Not Found error without path disclosure."
        }
    ]

    client = current_app.test_client()
    results = []

    for tc in test_cases:
        # Run Vulnerable Test
        v_resp = client.get(tc["vulnerable_path"])
        v_status = v_resp.status_code
        v_body = v_resp.get_data(as_text=True)
        v_content_type = v_resp.headers.get("Content-Type", "")
        v_passed = (v_status == tc["expected_vulnerable_status"])

        # Run Secure Test
        s_resp = client.get(tc["secure_path"])
        s_status = s_resp.status_code
        s_body = s_resp.get_data(as_text=True)
        s_content_type = s_resp.headers.get("Content-Type", "")
        s_passed = (s_status in (tc["expected_secure_status"], 404, 403) and s_status != 200 if tc["expected_secure_status"] in (403, 404) else s_status == tc["expected_secure_status"])

        results.append({
            "id": tc["id"],
            "name": tc["name"],
            "resource": tc["resource"],
            "description": tc["description"],
            "vulnerable": {
                "path": tc["vulnerable_path"],
                "expected_status": tc["expected_vulnerable_status"],
                "actual_status": v_status,
                "content_type": v_content_type,
                "passed": v_passed,
                "headers": dict(v_resp.headers),
                "snippet": v_body[:250] + ("..." if len(v_body) > 250 else "")
            },
            "secure": {
                "path": tc["secure_path"],
                "expected_status": tc["expected_secure_status"],
                "actual_status": s_status,
                "content_type": s_content_type,
                "passed": s_passed,
                "headers": dict(s_resp.headers),
                "snippet": s_body[:250] + ("..." if len(s_body) > 250 else "")
            },
            "overall_pass": v_passed and s_passed
        })

    return jsonify({
        "success": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(results),
        "passed_tests": sum(1 for r in results if r["overall_pass"]),
        "results": results
    })
