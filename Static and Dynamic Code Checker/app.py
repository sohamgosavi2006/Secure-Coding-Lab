"""
JavaCodeCheck - Interactive Static and Runtime Code Analysis Lab
Flask backend service orchestrating real Java analysis tools:
PMD, SpotBugs, JUnit 5, and JaCoCo.
"""

import os
import sys
from flask import Flask, render_template, request, jsonify
from pathlib import Path

# Add current directory to path for runner module
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import runner

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status", methods=["GET"])
def api_status():
    """Return availability and versions of all 4 analysis tools."""
    tools = runner.check_tools_status()
    all_ready = all(t.get("available", False) for t in tools.values())
    return jsonify({
        "status": "ready" if all_ready else "degraded",
        "tools": tools,
        "scenarios_count": len(runner.SAMPLE_SCENARIOS)
    })

@app.route("/api/scenarios", methods=["GET"])
def api_scenarios():
    """Return all predefined educational Java code scenarios."""
    return jsonify({
        "success": True,
        "scenarios": list(runner.SAMPLE_SCENARIOS.values())
    })

@app.route("/api/source", methods=["GET"])
def api_source():
    """Load actual Java source code from the real files."""
    file_path = request.args.get("file", "")
    if not file_path:
        return jsonify({"success": False, "error": "Missing 'file' parameter"}), 400
    
    data = runner.get_source_file_content(file_path)
    if "error" in data:
        return jsonify({"success": False, "error": data["error"]}), 404
    
    return jsonify({"success": True, "data": data})

@app.route("/api/compile", methods=["POST"])
def api_compile():
    """Compile Java source and test classes with javac."""
    res = runner.compile_project()
    return jsonify(res)

@app.route("/api/pmd", methods=["POST"])
def api_pmd():
    """Run PMD static analysis on genuine source files."""
    data = request.get_json() or {}
    target_path = data.get("target_path")
    res = runner.run_pmd(target_path=target_path)
    return jsonify(res)

@app.route("/api/spotbugs", methods=["POST"])
def api_spotbugs():
    """Run SpotBugs static analysis on compiled bytecode."""
    data = request.get_json() or {}
    class_filter = data.get("class_filter")
    res = runner.run_spotbugs(class_filter=class_filter)
    return jsonify(res)

@app.route("/api/junit", methods=["POST"])
def api_junit():
    """Execute genuine JUnit 5 tests and capture JaCoCo coverage."""
    data = request.get_json() or {}
    test_class = data.get("test_class")
    res = runner.run_junit(test_class=test_class)
    return jsonify(res)

@app.route("/api/comparison", methods=["GET"])
def api_comparison():
    """
    Run comprehensive analysis across all 4 scenarios for both vulnerable
    and corrected versions to populate the side-by-side comparison matrix.
    """
    # 1. Run full PMD
    pmd_res = runner.run_pmd()
    pmd_findings = pmd_res.get("findings", [])

    # 2. Run full SpotBugs
    spotbugs_res = runner.run_spotbugs()
    spotbugs_findings = spotbugs_res.get("findings", [])

    # 3. Run full JUnit & JaCoCo
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

        # PMD matches
        v_pmd = [f for f in pmd_findings if Path(v_file).name in f.get("file", "")]
        f_pmd = [f for f in pmd_findings if Path(f_file).name in f.get("file", "")]

        # SpotBugs matches
        v_sb = [f for f in spotbugs_findings if v_class in f.get("class_name", "")]
        f_sb = [f for f in spotbugs_findings if f_class in f.get("class_name", "")]

        # JUnit tests
        suite_tests = [t for t in tests if t.get("class_name") == t_class]
        v_tests = [t for t in suite_tests if "vulnerable" in t.get("name", "").lower()]
        f_tests = [t for t in suite_tests if "fixed" in t.get("name", "").lower()]

        # JaCoCo coverage
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5051))
    print("================================================================")
    print(" JavaCodeCheck - Interactive Static & Dynamic Code Analysis Lab")
    print(f" Running on http://127.0.0.1:{port} and http://localhost:{port}")
    print("================================================================")
    app.run(host="0.0.0.0", port=port, debug=True)
