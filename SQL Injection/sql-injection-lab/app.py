"""
SecureLab — SQL Injection Explorer
Practical Demonstration Project for B.Tech Minor in Cyber Security (Secure Coding)

DISCLAIMER:
This application is strictly for local educational use in an isolated sandbox.
The vulnerable endpoint contains an intentional SQL Injection vulnerability
for teaching purposes only. Never use string concatenation for SQL queries
in production code. Always use parameterized queries / prepared statements.
"""

import os
import sqlite3
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "securelab.db")

# ---------------------------------------------------------------------------
# Database Initialization & Reset
# ---------------------------------------------------------------------------

INITIAL_USERS = [
    (1, "admin", "AdminSecret2026!", "Dr. Alice Vance", "Administrator", "alice.admin@securelab.local"),
    (2, "john_doe", "StudentPass123", "John Doe", "Student", "john.doe@student.local"),
    (3, "sarah_connor", "CyberGuard#42", "Sarah Connor", "Security Analyst", "sarah.c@analyst.local"),
]

def get_db_connection():
    """Create a connection to the local SQLite demonstration database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize or reset the SQLite demonstration database with clean seed data."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Drop existing table to ensure clean state
    cursor.execute("DROP TABLE IF EXISTS users")

    # Create users table
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

    # Populate with fictional demonstrative users
    cursor.executemany("""
        INSERT INTO users (id, username, password, full_name, role, email)
        VALUES (?, ?, ?, ?, ?, ?)
    """, INITIAL_USERS)

    conn.commit()
    conn.close()

# Ensure database exists at startup
init_db()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the single-page application interface."""
    return render_template("index.html")

@app.route("/api/vulnerable/login", methods=["POST"])
def vulnerable_login():
    """
    ⚠️ INTENTIONALLY VULNERABLE ENDPOINT (FOR LOCAL EDUCATIONAL USE ONLY)
    Demonstrates SQL Injection via direct string concatenation.
    Input becomes executable SQL code rather than treated as pure data.
    """
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # VULNERABLE SQL CONCATENATION:
    # Directly embedding user input into the SQL string without sanitization or parameterization
    raw_query = (
        f"SELECT id, username, full_name, role, email "
        f"FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Executes directly without parameter binding
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

            # Check if this was an injection bypass
            # (e.g. user got authenticated as admin without providing the actual admin password)
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
        # Syntax errors occur when injection leaves unbalanced quotes or illegal syntax
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
    """
    🛡️ SECURE ENDPOINT
    Uses Parameterized Queries (Prepared Statements).
    User input is sent separately as bound parameters, NEVER interpreted as SQL code.
    """
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # SECURE PARAMETERIZED QUERY:
    # Uses '?' placeholders for parameters in SQLite
    query_template = (
        "SELECT id, username, full_name, role, email "
        "FROM users "
        "WHERE username = ? AND password = ?"
    )
    bound_params = (username, password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # SQLite pre-compiles the query template; parameters are strictly treated as literal data
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
    """Reset the database to the default initial demonstration state."""
    init_db()
    return jsonify({
        "success": True,
        "message": "Demonstration database successfully reset to clean initial state."
    })

@app.route("/api/status", methods=["GET"])
def status():
    """Return system status and list of demo users (without passwords)."""
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
# Main Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print("================================================================")
    print(" SecureLab — SQL Injection Explorer (Educational Sandbox)")
    print(f" Running on http://127.0.0.1:{port} and http://localhost:{port}")
    print("================================================================")
    app.run(host="0.0.0.0", port=port, debug=True)
