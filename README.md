# Minor Degree Secure Coding Laboratory 

A unified educational web application developed for the Minor Degree in Cyber Security and Secure Coding. The suite provides interactive, hands-on demonstrations comparing vulnerable implementations against secure, hardened countermeasures across three core cybersecurity domains.

---

## Project Overview

This laboratory suite combines three guided security demonstration modules within a unified master portal:

- **Project 1 — SQL Injection Explorer**: Demonstrates SQL Injection (CWE-89) and the defense provided by parameterized queries (prepared statements). Includes a live SQL query syntax inspector, pre-seeded synthetic user accounts, interactive authentication bypass payloads (`' OR 1=1 --`), and one-click database reset capabilities.
- **Project 2 — Java Code Checker**: Demonstrates static code analysis, bytecode inspection, dynamic unit testing, and runtime code coverage in Java. Uses PMD (AST rule scanning), SpotBugs (bytecode bug pattern analysis), JUnit 5 (runtime assertions), and JaCoCo (line/branch coverage) to evaluate four real-world software security and reliability scenarios:
  1. *Null Pointer Dereference* (CWE-476)
  2. *Array Boundary Validation* (CWE-129 / CWE-193)
  3. *Suppressed Exception Handling* (CWE-390 / CWE-391)
  4. *Unclosed I/O Resource Leaks* (CWE-404 / CWE-775)
- **Project 3 — Web Server Attack & Defense Simulator**: Demonstrates directory listing misconfigurations (CWE-548) and sensitive file exposure in public web roots (CWE-552). Illustrates why disabling directory browsing alone is insufficient without segregating confidential assets outside the document root, and provides countermeasures including Flask route protection, strict allowlisting, defensive HTTP headers, and Apache (`Options -Indexes`) and Nginx (`autoindex off`) configuration examples.

Each module provides side-by-side vulnerable versus secure comparisons to clearly illustrate underlying root causes and remediation techniques.

---

## Technology Stack

- **Backend Web Server**: Python 3.9+ with Flask
- **Frontend Interface**: HTML5, Vanilla CSS, Vanilla JavaScript (responsive multi-panel layout, light/dark theme toggle, interactive request/response inspectors, and live code viewers)
- **Database**: SQLite 3 (sample training database for SQL Injection demonstrations)
- **Java Analysis & Testing Tools**:
  - Java 17+ bytecode target (`--release 17`)
  - Apache Maven (standard build configuration via `pom.xml`)
  - PMD 7.0.0 (AST-based static source code analysis)
  - SpotBugs 4.8.6 with ASM 9.11 (bytecode static analysis engine)
  - JUnit 5 Console Standalone 1.10.2 (dynamic runtime test execution)
  - JaCoCo 0.8.12 (runtime code coverage agent and reporting CLI)

---

## Prerequisites

Before running the application, ensure the following software is installed on your system:

- **Python**: Python 3.9 or higher and `pip` (`python3 --version`, `pip --version`)
- **Java**: Java Development Kit (JDK) 17 or higher (`java -version`, `javac -version`)
- **Maven** (Optional): Apache Maven 3.8+ (`mvn -version`) if you wish to run standalone builds and reports directly via `pom.xml`

---

## Installation and Running Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/sohamgosavi2006/Secure-Coding-Lab.git
cd Secure-Coding-Lab
```

### 2. Set Up Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
# On Windows use: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Launch the Unified Master Portal

Start the Flask application:

```bash
python app.py
```

Upon startup, the console displays:

```text
================================================================
 Secure Coding Laboratory Suite — Master Portal
 Combined Projects: SQL Injection Explorer + JavaCodeCheck Lab
 Running on http://127.0.0.1:5050 and http://localhost:5050
================================================================
```

Open your web browser and navigate to:

```text
http://127.0.0.1:5050
```

---

### Java Code Checker Setup & Execution

The Java Code Checker execution engine (`runner.py`) uses Java 17+ and bundles required tool binaries under `Static and Dynamic Code Checker/tools/`. Ensure `javac` and `java` are available in your system path.

To run tests and compile the Java project independently using Maven:

```bash
cd "Static and Dynamic Code Checker"
mvn clean test
```

---

### Running Sub-Projects Standalone (Optional)

Each sub-project can also be executed independently from its respective folder:

- **SQL Injection Explorer**:
  ```bash
  cd "SQL Injection/sql-injection-lab"
  python app.py
  # Accessible at http://127.0.0.1:5050
  ```

- **Java Code Checker**:
  ```bash
  cd "Static and Dynamic Code Checker"
  python app.py
  # Accessible at http://127.0.0.1:5051
  ```

- **Web Server Attack Simulator**:
  ```bash
  cd "Web Server Attack"
  python app.py
  # Accessible at http://127.0.0.1:5052
  ```

- **Web Server Attack Automated Unit Tests**:
  ```bash
  python -m unittest discover -s "Web Server Attack/tests"
  ```

---

## Local Demonstration Safety

This application is intended solely for educational demonstrations in a controlled local environment. Project 3 deliberately includes a vulnerable web server simulation to demonstrate the consequences of configuration mistakes and exposed web roots. All sample credentials, configuration keys, database dumps, and API tokens used across the demonstrations are purely synthetic training fixtures. Do not deploy this application on public or untrusted networks in its vulnerable state.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
