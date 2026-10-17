# WebShield Lab — Web Server Attack & Defense Simulator

**Course:** Minor Degree in Cyber Security &bull; Secure Coding (Project 3)  
**Academic Year:** 2026  
**Focus:** Directory Listing & Sensitive File Exposure (CWE-548 & CWE-552)

---

## 1. Project Purpose

WebShield Lab is an educational sandbox designed to demonstrate web server misconfiguration vulnerabilities and their definitive countermeasures.

Specifically, it illustrates how combining:
1. **Directory Indexing Enabled** (`Options +Indexes` / `autoindex on;`), and
2. **Sensitive Files Placed Inside Public Web Root** (`demo-config.txt`, `backup-demo.txt`)

allows an unauthenticated visitor to perform reconnaissance and extract confidential infrastructure tokens. It then demonstrates the defense-in-depth countermeasures required to protect modern web infrastructure.

---

## 2. Weakness Analysis

### Weakness A: Directory Listing Enabled (CWE-548)
- **Mechanism:** When a request is made to a directory (e.g., `/vulnerable/browse`) that lacks a default index document or where indexing directives are enabled, the web server generates an HTML table containing all filenames, file sizes, and timestamps in that folder.
- **Impact:** Reveals sensitive filenames (e.g. `demo-config.txt`, `backup-demo.txt`), hidden subdirectories, and application architecture.

### Weakness B: Sensitive File Inside Public Document Root (CWE-552 / CWE-200)
- **Mechanism:** Confidential files stored within the public document root (such as `/var/www/html/demo-config.txt`) are directly served by the HTTP daemon without authorization checks.
- **Impact:** Directly discloses internal database passwords, API keys, and environment variables.

### The Fundamental Security Lesson
> **Critical Insight:** Disabling directory listing alone does **NOT** secure a confidential file if that file remains in the public web root. An attacker who guesses, brute-forces, or finds the URL in logs or code can still retrieve the file directly via `GET /files/demo-config.txt`. True security requires both disabling directory indexing **and** segregating sensitive assets outside the web root.

---

## 3. Defense-in-Depth Countermeasures

1. **Disable Directory Indexing:**
   - **Apache (`httpd.conf` / `.htaccess`):**
     ```apache
     <Directory "/var/www/html">
         Options -Indexes
     </Directory>
     ```
   - **Nginx (`nginx.conf`):**
     ```nginx
     server {
         location / {
             autoindex off;
         }
     }
     ```
   - Server returns `403 Forbidden` for directory requests.

2. **Segregate Confidential Files Outside the Document Root:**
   - Store configuration files in non-public operating system directories (e.g., `/etc/app/` or `fixtures/private_storage/`).
   - Never place credentials, SQLite databases, `.env` files, or backup archives inside the publicly served tree.

3. **Strict Resource Allowlisting:**
   - Only serve explicitly approved static assets (e.g., `index.html`, `about.html`).

4. **Defensive Response Headers:**
   - Include `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing.
   - Include `X-Frame-Options: DENY` to mitigate clickjacking.

---

## 4. Architecture & Route Specification

The module is implemented as a modular Flask Blueprint (`web_server_attack_bp`) mounted under `/web-server-attack`:

| Route | Method | Mode | Purpose |
|---|---|---|---|
| `/web-server-attack/api/status` | `GET` | API | Returns directory structures and environment metadata |
| `/web-server-attack/vulnerable/browse` | `GET` | Vulnerable | Returns directory listing HTML or JSON (CWE-548) |
| `/web-server-attack/vulnerable/files/<filename>` | `GET` | Vulnerable | Directly serves requested file from public web root (CWE-552) |
| `/web-server-attack/secure/browse` | `GET` | Secure | Returns `403 Forbidden` denying directory indexing |
| `/web-server-attack/secure/files/<filename>` | `GET` | Secure | Serves allowlisted assets only; denies private files |
| `/web-server-attack/api/source?target=<vuln\|sec>` | `GET` | API | Loads genuine server source lines with highlighting |
| `/web-server-attack/api/compare-tests` | `GET` | API | Executes 5 live comparative tests across both modes |

---

## 5. Running the Tests

To execute the automated unit test suite:
```bash
./venv/bin/python3 -m unittest "Web Server Attack/tests/test_web_server_attack.py"
```
All tests verify both vulnerable behaviors and secure countermeasures under controlled localhost execution.
