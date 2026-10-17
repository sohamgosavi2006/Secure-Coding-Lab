"""
Secure Coding Laboratory Suite — Unified Master Portal
Combines:
1. SecureLab — SQL Injection Explorer (Web Vulnerability & Prepared Statements)
2. JavaCodeCheck — Interactive Static & Runtime Code Analysis Lab (PMD, SpotBugs, JUnit 5, JaCoCo)
3. Projects Architecture & Technical Specification Hub
"""

import os
import sys
import sqlite3
from pathlib import Path
from flask import Flask, render_template, request, jsonify

ROOT_DIR = Path(__file__).resolve().parent
SQLI_DIR = ROOT_DIR / "SQL Injection" / "sql-injection-lab"
JAVA_DIR = ROOT_DIR / "Static and Dynamic Code Checker"
WEB_ATTACK_DIR = ROOT_DIR / "Web Server Attack"

# Add subproject directories to sys.path
sys.path.insert(0, str(SQLI_DIR))
sys.path.insert(0, str(JAVA_DIR))
sys.path.insert(0, str(WEB_ATTACK_DIR))

import runner
from routes import web_server_attack_bp

app = Flask(
    __name__,
    template_folder=str(ROOT_DIR / "templates"),
    static_folder=str(ROOT_DIR / "static")
)

# Register Web Server Attack Blueprint (Project 3)
app.register_blueprint(web_server_attack_bp)

# ---------------------------------------------------------------------------
# SQL Injection Database Initialization
# ---------------------------------------------------------------------------
DB_PATH = SQLI_DIR / "securelab.db"

INITIAL_USERS = [
    (1, "admin", "AdminSecret2026!", "Dr. Alice Vance", "Administrator", "alice.admin@securelab.local"),
    (2, "john_doe", "StudentPass123", "John Doe", "Student", "john.doe@student.local"),
    (3, "sarah_connor", "CyberGuard#42", "Sarah Connor", "Security Analyst", "sarah.c@analyst.local"),
]

def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """)
    cursor.executemany("""
        INSERT INTO users (id, username, password, full_name, role, email)
        VALUES (?, ?, ?, ?, ?, ?)
    """, INITIAL_USERS)
    conn.commit()
    conn.close()

# Ensure database exists
init_db()

# ---------------------------------------------------------------------------
# Master Portal Page
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Serve the unified multi-project portal."""
    return render_template("index.html")

# ---------------------------------------------------------------------------
# SQL Injection Lab Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/vulnerable/login", methods=["POST"])
def vulnerable_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    raw_query = (
        f"SELECT id, username, full_name, role, email "
        f"FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(raw_query)
        row = cursor.fetchone()

        if row:
            authenticated_user = {
                "id": row["id"],
                "username": row["username"],
                "full_name": row["full_name"],
                "role": row["role"],
                "email": row["email"],
            }
            is_bypass = (
                ("'" in username or "--" in username or "OR" in username.upper())
                and password != "AdminSecret2026!"
            )
            explanation = (
                "Authentication succeeded because the database query returned a matching user record. "
                "Because user input was concatenated directly into the query, input such as `' OR 1=1 --` "
                "modified the query's boolean logic, causing the WHERE clause to evaluate to TRUE for all rows. "
                "The database returned the first matching record (Administrator) without validating the password."
                if is_bypass else
                "Authentication succeeded using valid matching credentials."
            )
            return jsonify({
                "success": True,
                "mode": "vulnerable",
                "constructed_query": raw_query,
                "authenticated_user": authenticated_user,
                "is_bypass": is_bypass,
                "message": "Login Successful",
                "explanation": explanation
            })
        else:
            return jsonify({
                "success": False,
                "mode": "vulnerable",
                "constructed_query": raw_query,
                "authenticated_user": None,
                "is_bypass": False,
                "message": "Login Rejected: No matching user record found",
                "explanation": "The constructed query was executed, but zero rows matched the WHERE condition."
            })
    except sqlite3.OperationalError as e:
        return jsonify({
            "success": False,
            "mode": "vulnerable",
            "constructed_query": raw_query,
            "authenticated_user": None,
            "is_bypass": False,
            "database_error": str(e),
            "message": "Database Syntax Error (Unbalanced Quotes or Malformed SQL)",
            "explanation": f"The unescaped input broke the SQL grammar: {e}. In real applications, this error confirms the presence of SQL injection to an attacker."
        }), 200
    finally:
        conn.close()

@app.route("/api/secure/login", methods=["POST"])
def secure_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    query_template = (
        "SELECT id, username, full_name, role, email "
        "FROM users "
        "WHERE username = ? AND password = ?"
    )
    bound_params = (username, password)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(query_template, bound_params)
        row = cursor.fetchone()

        if row:
            authenticated_user = {
                "id": row["id"],
                "username": row["username"],
                "full_name": row["full_name"],
                "role": row["role"],
                "email": row["email"],
            }
            return jsonify({
                "success": True,
                "mode": "secure",
                "query_template": query_template,
                "bound_parameters": [username, "••••••••" if password else ""],
                "authenticated_user": authenticated_user,
                "message": "Login Successful with Valid Credentials",
                "explanation": "The database looked for an exact match for both username and password as literal string values."
            })
        else:
            return jsonify({
                "success": False,
                "mode": "secure",
                "query_template": query_template,
                "bound_parameters": [username, "••••••••" if password else ""],
                "authenticated_user": None,
                "message": "Login Rejected: Invalid Credentials",
                "explanation": (
                    "The database treated the input strictly as literal string values. "
                    f"It searched for a user whose exact username column equals '{username}'. "
                    "Special characters such as ' and -- were never parsed as SQL syntax, preventing injection."
                )
            })
    finally:
        conn.close()

@app.route("/api/reset", methods=["POST"])
def reset_database():
    init_db()
    return jsonify({
        "success": True,
        "message": "Demonstration database successfully reset to clean initial state."
    })

@app.route("/api/status", methods=["GET"])
def sqli_status():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, role, email FROM users ORDER BY id ASC")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return jsonify({
        "status": "ready",
        "demo_users": users
    })

# ---------------------------------------------------------------------------
# JavaCodeCheck Lab Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/java/status", methods=["GET"])
def java_status():
    tools = runner.check_tools_status()
    all_ready = all(t.get("available", False) for t in tools.values())
    return jsonify({
        "status": "ready" if all_ready else "degraded",
        "tools": tools,
        "scenarios_count": len(runner.SAMPLE_SCENARIOS)
    })

@app.route("/api/java/scenarios", methods=["GET"])
def java_scenarios():
    return jsonify({
        "success": True,
        "scenarios": list(runner.SAMPLE_SCENARIOS.values())
    })

@app.route("/api/java/source", methods=["GET"])
def java_source():
    file_path = request.args.get("file", "")
    if not file_path:
        return jsonify({"success": False, "error": "Missing 'file' parameter"}), 400
    data = runner.get_source_file_content(file_path)
    if "error" in data:
        return jsonify({"success": False, "error": data["error"]}), 404
    return jsonify({"success": True, "data": data})

@app.route("/api/java/compile", methods=["POST"])
def java_compile():
    return jsonify(runner.compile_project())

@app.route("/api/java/pmd", methods=["POST"])
def java_pmd():
    data = request.get_json() or {}
    target_path = data.get("target_path")
    return jsonify(runner.run_pmd(target_path=target_path))

@app.route("/api/java/spotbugs", methods=["POST"])
def java_spotbugs():
    data = request.get_json() or {}
    class_filter = data.get("class_filter")
    return jsonify(runner.run_spotbugs(class_filter=class_filter))

@app.route("/api/java/junit", methods=["POST"])
def java_junit():
    data = request.get_json() or {}
    test_class = data.get("test_class")
    return jsonify(runner.run_junit(test_class=test_class))

@app.route("/api/java/comparison", methods=["GET"])
def java_comparison():
    pmd_res = runner.run_pmd()
    pmd_findings = pmd_res.get("findings", [])

    spotbugs_res = runner.run_spotbugs()
    spotbugs_findings = spotbugs_res.get("findings", [])

    junit_res = runner.run_junit()
    tests = junit_res.get("tests", [])
    coverage = junit_res.get("coverage", {}).get("files", {})

    matrix = []
    for sc_id, sc in runner.SAMPLE_SCENARIOS.items():
        v_file = sc["vulnerable_file"]
        f_file = sc["fixed_file"]
        v_class = sc["vulnerable_class"]
        f_class = sc["fixed_class"]
        t_class = sc["test_class"]

        v_pmd = [f for f in pmd_findings if Path(v_file).name in f.get("file", "")]
        f_pmd = [f for f in pmd_findings if Path(f_file).name in f.get("file", "")]

        v_sb = [f for f in spotbugs_findings if v_class in f.get("class_name", "")]
        f_sb = [f for f in spotbugs_findings if f_class in f.get("class_name", "")]

        suite_tests = [t for t in tests if t.get("class_name") == t_class]
        v_tests = [t for t in suite_tests if "vulnerable" in t.get("name", "").lower()]
        f_tests = [t for t in suite_tests if "fixed" in t.get("name", "").lower()]

        v_cov = coverage.get(Path(v_file).name, {})
        f_cov = coverage.get(Path(f_file).name, {})

        matrix.append({
            "scenario": sc,
            "vulnerable": {
                "file": v_file,
                "pmd_count": len(v_pmd),
                "pmd_findings": v_pmd,
                "spotbugs_count": len(v_sb),
                "spotbugs_findings": v_sb,
                "tests_total": len(v_tests),
                "tests_passed": len([t for t in v_tests if t.get("status") == "PASSED"]),
                "tests_failed": len([t for t in v_tests if t.get("status") == "FAILED"]),
                "coverage_pct": v_cov.get("line_coverage_percentage", 0.0)
            },
            "fixed": {
                "file": f_file,
                "pmd_count": len(f_pmd),
                "pmd_findings": f_pmd,
                "spotbugs_count": len(f_sb),
                "spotbugs_findings": f_sb,
                "tests_total": len(f_tests),
                "tests_passed": len([t for t in f_tests if t.get("status") == "PASSED"]),
                "tests_failed": len([t for t in f_tests if t.get("status") == "FAILED"]),
                "coverage_pct": f_cov.get("line_coverage_percentage", 0.0)
            }
        })

    return jsonify({
        "success": True,
        "matrix": matrix,
        "overall_coverage": junit_res.get("coverage", {}).get("overall_line_coverage", 0.0),
        "total_tests": junit_res.get("total_tests", 0)
    })

# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print("================================================================")
    print(" Secure Coding Laboratory Suite — Master Portal")
    print(" Combined Projects: SQL Injection Explorer + JavaCodeCheck Lab")
    print(f" Running on http://127.0.0.1:{port} and http://localhost:{port}")
    print("================================================================")
    app.run(host="0.0.0.0", port=port, debug=True)
