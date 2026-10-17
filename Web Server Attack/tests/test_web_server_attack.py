"""
Unit Tests for WebShield Lab — Web Server Attack and Defense Simulator (Project 3)
Verifies:
1. Directory listing vulnerability (CWE-548).
2. Sensitive file exposure in public web root (CWE-552).
3. Defensive countermeasures:
   - Directory indexing disabled (403 Forbidden).
   - Strict allowlisting of public resources.
   - Non-public files segregated and blocked.
   - Path traversal prevention.
4. Source code inspection API allowlist integrity.
5. Comparison test suite execution.
"""

import sys
import unittest
from pathlib import Path
from flask import Flask

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from routes import web_server_attack_bp, ALLOWED_PUBLIC_FILES

class WebServerAttackTestCase(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        self.app.register_blueprint(web_server_attack_bp)
        self.client = self.app.test_client()

    # -------------------------------------------------------------------------
    # Vulnerable Scenario Tests
    # -------------------------------------------------------------------------
    def test_vulnerable_directory_listing_html(self):
        """Vulnerable server must allow directory browsing and expose file list."""
        resp = self.client.get("/web-server-attack/vulnerable/browse")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers.get("Content-Type", ""))
        body = resp.get_data(as_text=True)
        self.assertIn("Index of /vulnerable/files/", body)
        self.assertIn("demo-config.txt", body)
        self.assertIn("backup-demo.txt", body)
        self.assertIn("SENSITIVE EXPOSED", body)

    def test_vulnerable_directory_listing_json(self):
        """Vulnerable directory listing must provide structured metadata in JSON."""
        resp = self.client.get("/web-server-attack/vulnerable/browse?format=json")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "vulnerable_directory_listing_enabled")
        file_names = [f["name"] for f in data["files"]]
        self.assertIn("demo-config.txt", file_names)
        self.assertIn("index.html", file_names)

    def test_vulnerable_file_serving_sensitive(self):
        """Vulnerable web root must disclose sensitive demo-config.txt when directly requested."""
        resp = self.client.get("/web-server-attack/vulnerable/files/demo-config.txt")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("DEMO_ONLY_TOKEN=FAKE-TRAINING-VALUE-987654321", body)
        self.assertIn("DB_PASSWORD=FAKE-DEMO-PASSWORD-XYZ123", body)

    def test_vulnerable_file_serving_public(self):
        """Vulnerable server must also serve legitimate public assets."""
        resp = self.client.get("/web-server-attack/vulnerable/files/index.html")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("Acme Global Systems", body)

    def test_vulnerable_path_traversal_blocked(self):
        """Lab containment must prevent arbitrary traversal outside the fixture root."""
        resp = self.client.get("/web-server-attack/vulnerable/files/../../routes.py")
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertIn("Path traversal rejected", data.get("error", ""))

    # -------------------------------------------------------------------------
    # Secure Countermeasure Tests
    # -------------------------------------------------------------------------
    def test_secure_directory_listing_prohibited(self):
        """Secure server must reject directory browsing with 403 Forbidden."""
        resp = self.client.get("/web-server-attack/secure/browse")
        self.assertEqual(resp.status_code, 403)
        body = resp.get_data(as_text=True)
        self.assertIn("403 Forbidden", body)
        self.assertIn("Directory Browsing Prohibited", body)

    def test_secure_directory_listing_json_prohibited(self):
        """Secure server JSON request must return 403 Forbidden."""
        resp = self.client.get("/web-server-attack/secure/browse?format=json")
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["status_code"], 403)
        self.assertIn("strictly prohibited", data.get("error", ""))

    def test_secure_file_serving_public_allowed(self):
        """Secure server must permit explicitly allowlisted public files."""
        resp = self.client.get("/web-server-attack/secure/files/index.html")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        body = resp.get_data(as_text=True)
        self.assertIn("Acme Global Systems", body)

    def test_secure_file_serving_sensitive_denied(self):
        """Secure server must reject requests for confidential files with 403 Forbidden."""
        resp = self.client.get("/web-server-attack/secure/files/demo-config.txt")
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertEqual(data["status_code"], 403)
        self.assertIn("Access Denied", data.get("error", ""))

    def test_secure_file_serving_unknown_denied(self):
        """Secure server must return 404 for unknown resources."""
        resp = self.client.get("/web-server-attack/secure/files/unknown-file.txt")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertEqual(data["status_code"], 404)

    # -------------------------------------------------------------------------
    # API & Inspector Tests
    # -------------------------------------------------------------------------
    def test_source_code_inspection_vulnerable(self):
        """Source inspection API must load genuine vulnerable code from routes.py."""
        resp = self.client.get("/web-server-attack/api/source?target=vulnerable")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("vulnerable_browse", data["raw_text"])
        self.assertTrue(any(line["highlight"] for line in data["code_lines"]))

    def test_source_code_inspection_secure(self):
        """Source inspection API must load genuine secure code from routes.py."""
        resp = self.client.get("/web-server-attack/api/source?target=secure")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertIn("secure_browse", data["raw_text"])
        self.assertTrue(any(line["highlight"] for line in data["code_lines"]))

    def test_source_code_inspection_invalid_target(self):
        """Source inspection API must reject arbitrary targets."""
        resp = self.client.get("/web-server-attack/api/source?target=arbitrary_file")
        self.assertEqual(resp.status_code, 400)

    def test_comparison_runner_suite(self):
        """Comparison test runner must execute all 5 cases and report pass."""
        resp = self.client.get("/web-server-attack/api/compare-tests")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["total_tests"], 5)
        self.assertEqual(data["passed_tests"], 5)

if __name__ == "__main__":
    unittest.main()
