# SecureLab — SQL Injection Explorer

**Course:** Secure Coding (Cyber Security Minor Degree)  
**Project:** Vulnerable vs. Secure Web Portal Practical Demonstration  
**Platform:** Python Flask, SQLite, HTML5, CSS3, Vanilla JavaScript  
**Environment:** Localhost (127.0.0.1:5000), Isolated Sandbox  

---

## 1. Project Overview

**SecureLab** is an educational laboratory designed to practically demonstrate **SQL Injection (CWE-89)** and its definitive mitigation using **Parameterized Queries (Prepared Statements)**.

It provides a side-by-side comparison between:
1. **A Vulnerable Implementation** that constructs database queries via unescaped string concatenation.
2. **A Secure Implementation** that pre-compiles query structure and treats user input as strictly bound parameters.

The application features a **Live SQL Inspector** that visualizes the exact query evaluated by the SQLite engine in real-time, plus a **Step-by-Step Guided Demo** that walks students and evaluators through the attack and defense.

---

## 2. Directory Structure

```text
sql-injection-lab/
├── app.py              # Flask server, SQLite initialization, API routes
├── securelab.db        # Local demonstration SQLite database (auto-created)
├── requirements.txt    # Python dependencies (Flask >= 3.0.0)
├── templates/
│   └── index.html      # Single-page application shell
├── static/
│   ├── style.css       # Design system matching reference aesthetic
│   └── app.js          # Interactive controller & 6-step guided tour engine
└── README.md           # Documentation & launch instructions
```

---

## 3. Quick Start (Running Locally on macOS)

### Prerequisites
- Python 3.9+ installed (`python3 --version`)

### Step 1: Open Terminal in the Project Directory
```bash
cd "sql-injection-lab"
```

### Step 2: Create and Activate a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python app.py
```

### Step 5: Open in Browser
Open your web browser and navigate to:
```text
http://127.0.0.1:5050
```
(or `http://localhost:5050`)

---

## 4. How the Practical Demonstration Works

### Fictional Test Accounts
The local SQLite database comes pre-seeded with 3 test accounts:

| Username | Role | Password |
|---|---|---|
| `admin` | Administrator | `AdminSecret2026!` |
| `john_doe` | Student | `StudentPass123` |
| `sarah_connor` | Security Analyst | `CyberGuard#42` |

---

### Step-by-Step Walkthrough

#### 1. Legitimate Authentication Test
- **Input:** Username `john_doe`, Password `StudentPass123`
- **Result:** Login successful for student John Doe in both vulnerable and secure modes.

#### 2. SQL Injection Authentication Bypass (Vulnerable Mode)
- **Input:** Username `' OR 1=1 --`, Password `[leave empty]`
- **Vulnerable Code Execution:**
  ```python
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
  ```
- **Resulting SQL Query:**
  ```sql
  SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = ''
  ```
- **Database Behavior:**
  - The single quote `'` closes the username literal.
  - `OR 1=1` forces the `WHERE` condition to always evaluate to `TRUE`.
  - The double dash `--` comments out the remainder of the query, completely eliminating the password check.
  - The query returns all records; SQLite fetches the first row, granting **instant administrative access** as `Dr. Alice Vance (admin)` without a password!

#### 3. Defense Verification (Secure Mode)
- **Input:** Same injection string: `' OR 1=1 --`
- **Secure Code Execution:**
  ```python
  query = "SELECT * FROM users WHERE username = ? AND password = ?"
  cursor.execute(query, (username, password))
  ```
- **Database Behavior:**
  - The SQLite query planner pre-compiles the template with `?` placeholders.
  - The parameter is treated strictly as literal data. The engine searches for a user whose literal username column equals the text string `"' OR 1=1 --"`.
  - No such user exists. The attack is **safely neutralized** and authentication is rejected.

---

## 5. Security Scope & Safety Guidelines

- **Isolated Sandbox:** The database is a local SQLite file (`securelab.db`) residing purely on your machine.
- **Localhost Only:** The Flask server binds exclusively to `127.0.0.1`.
- **Read-Only Authentication Logic:** No destructive queries (`DROP`, `DELETE`, `UPDATE`) are executed.
- **Reset Feature:** Clicking **Reset demo** at any time restores the database to its pristine default state.
