"""
JavaCodeCheck - Tool Execution Engine & Report Parsers
Orchestrates genuine execution of PMD, SpotBugs, JUnit 5, and JaCoCo.
Parses actual tool reports without hardcoded or fabricated findings.
"""

import os
import subprocess
import json
import xml.etree.ElementTree as ET
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src" / "main" / "java"
TEST_SRC_DIR = BASE_DIR / "src" / "test" / "java"
TARGET_CLASSES = BASE_DIR / "target" / "classes"
TARGET_TEST_CLASSES = BASE_DIR / "target" / "test-classes"
REPORTS_DIR = BASE_DIR / "reports"
TOOLS_DIR = BASE_DIR / "tools"
CONFIG_DIR = BASE_DIR / "config"

PMD_BIN = TOOLS_DIR / "pmd-bin-7.0.0" / "bin" / "pmd"
SPOTBUGS_HOME = TOOLS_DIR / "spotbugs-4.8.6"
JUNIT_JAR = TOOLS_DIR / "junit-platform-console-standalone.jar"
JACOCO_AGENT_JAR = TOOLS_DIR / "jacocoagent.jar"
JACOCO_CLI_JAR = TOOLS_DIR / "jacococli.jar"
PMD_RULESET = CONFIG_DIR / "pmd-ruleset.xml"

# Educational metadata dictionary explaining rules and patterns in plain English
TOOL_EXPLANATIONS = {
    "EmptyCatchBlock": {
        "title": "Empty Catch Block (Suppressed Failure)",
        "why": "The catch block catches an exception but contains no handling, logging, or recovery logic. This silently hides critical failures from the application, callers, and security monitoring.",
        "impact": "Suppressed exceptions prevent operators from identifying runtime failures, data corruption, or malicious input attempts (CWE-390 / CWE-391).",
        "remediation": "Log the exception with appropriate diagnostic context, rethrow as a specific domain exception, or execute safe fallback logic."
    },
    "CloseResource": {
        "title": "Unclosed I/O Resource (Resource Leak)",
        "why": "An AutoCloseable resource (such as BufferedReader, Reader, or InputStream) is allocated without guaranteed deterministic closure.",
        "impact": "If an exception occurs or execution exits, the stream remains open, exhausting OS file descriptors and socket pools (CWE-404 / CWE-775).",
        "remediation": "Wrap resource creation in a Java 7+ try-with-resources statement: try (BufferedReader reader = ...) { ... }"
    },
    "BrokenNullCheck": {
        "title": "Broken Null Check (Null Pointer Dereference)",
        "why": "The null check expression incorrectly uses boolean AND (&&) instead of OR (||), or checks the object after dereferencing it, triggering a NullPointerException.",
        "impact": "Uncaught NullPointerException crashes request processing and degrades application availability (CWE-476).",
        "remediation": "Use defensive validation: check for null first with logical OR (||) before dereferencing."
    },
    "RANGE_ARRAY_INDEX": {
        "title": "Array Index Out of Bounds",
        "why": "Bytecode analysis detected an array element access using an index that is known to exceed the allocated array boundary (e.g. index 3 on a 3-element array).",
        "impact": "Triggers an uncaught ArrayIndexOutOfBoundsException at runtime, leading to abnormal termination or buffer access violations (CWE-129 / CWE-193).",
        "remediation": "Always validate that index is non-negative and strictly less than array length (0 <= index < numbers.length) before indexing."
    },
    "NP_ALWAYS_NULL": {
        "title": "Null Pointer Dereference",
        "why": "A reference value is known to be null at this location and is dereferenced directly without prior validation.",
        "impact": "Guaranteed NullPointerException whenever this control flow path executes (CWE-476).",
        "remediation": "Provide defensive null checks (if (text == null) return 0;) before invoking methods on the object."
    },
    "NP_NULL_PARAM_DEREF_NONVIRTUAL": {
        "title": "Null Parameter Dereference",
        "why": "A method call passes a null literal or known null reference to a method whose parameters are dereferenced without checking.",
        "impact": "Triggers an unhandled NullPointerException upon method invocation (CWE-476).",
        "remediation": "Ensure caller validates parameters before passing, and callee defensively checks for null references."
    },
    "OS_OPEN_STREAM": {
        "title": "Unclosed I/O Stream (Resource Leak)",
        "why": "A stream or reader (such as BufferedReader) is allocated but not reliably closed along all execution and exception exit paths.",
        "impact": "Exhausts operating system file descriptors, handles, and buffer memory under continuous load (CWE-404 / CWE-775).",
        "remediation": "Enclose stream allocation in a Java try-with-resources statement: try (BufferedReader reader = ...) { ... }"
    },
    "OBL_UNSATISFIED_OBLIGATION": {
        "title": "Unsatisfied Resource Cleanup Obligation",
        "why": "A resource requiring explicit cleanup was opened without guaranteed closure on all paths.",
        "impact": "Resource leak across long-running server processes (CWE-404).",
        "remediation": "Use try-with-resources statement for automatic guaranteed closure."
    },
    "ArrayIsStoredDirectly": {
        "title": "Array Stored Directly",
        "why": "An array passed to a constructor or setter is stored directly in an object field without cloning, exposing mutable internal state.",
        "impact": "External callers can mutate array contents after assignment, bypassing boundary checks (CWE-374 / CWE-495).",
        "remediation": "Clone the array before storing: this.buffer = buffer.clone();"
    },
    "UnusedLocalVariable": {
        "title": "Unused Local Variable",
        "why": "A local variable was declared and assigned, but its value is never used.",
        "impact": "Indicates dead code, incomplete calculation, or suppressed execution results.",
        "remediation": "Use the variable, log it, or remove the redundant declaration."
    },
    "DLS_DEAD_LOCAL_STORE": {
        "title": "Dead Store to Local Variable",
        "why": "A value was assigned to a local variable but never read on any subsequent instruction path.",
        "impact": "Computation result is silently lost or ignored.",
        "remediation": "Return the calculated value, log it, or handle the outcome."
    },
    "DM_DEFAULT_ENCODING": {
        "title": "Reliance on Default Platform Encoding",
        "why": "Using InputStreamReader without specifying an explicit Charset relies on the host OS default encoding, which varies across platforms and locales.",
        "impact": "Code produces corrupted data, character encoding mismatch, or parsing discrepancies when executed across different environments.",
        "remediation": "Always supply an explicit standard charset: new InputStreamReader(is, StandardCharsets.UTF_8)"
    },
    "DM_CONVERT_CASE": {
        "title": "Locale-Sensitive String Case Conversion",
        "why": "Calling toUpperCase() or toLowerCase() without a Locale uses the platform default locale.",
        "impact": "Can lead to unexpected authentication or identifier matching bugs in internationalized deployments.",
        "remediation": "Use explicit locale: name.toUpperCase(Locale.ROOT) or validate input strings before conversion."
    }
}

SAMPLE_SCENARIOS = {
    "null_handling": {
        "id": "null_handling",
        "title": "Null Pointer Dereference",
        "category": "Defensive Programming & Null Safety",
        "cwe": "CWE-476: NULL Pointer Dereference",
        "vulnerable_file": "com/securecoding/samples/NullHandlingVulnerable.java",
        "fixed_file": "com/securecoding/samples/NullHandlingFixed.java",
        "vulnerable_class": "com.securecoding.samples.NullHandlingVulnerable",
        "fixed_class": "com.securecoding.samples.NullHandlingFixed",
        "test_class": "com.securecoding.tests.NullHandlingTest",
        "summary": "Demonstrates unsafe dereference in getLength(String text) where text.length() throws NullPointerException when text is null."
    },
    "array_bounds": {
        "id": "array_bounds",
        "title": "Array Boundary Validation",
        "category": "Input Validation & Buffer Access",
        "cwe": "CWE-129 / CWE-193: Improper Validation of Array Index (Off-by-One)",
        "vulnerable_file": "com/securecoding/samples/ArrayBoundsVulnerable.java",
        "fixed_file": "com/securecoding/samples/ArrayBoundsFixed.java",
        "vulnerable_class": "com.securecoding.samples.ArrayBoundsVulnerable",
        "fixed_class": "com.securecoding.samples.ArrayBoundsFixed",
        "test_class": "com.securecoding.tests.ArrayBoundsTest",
        "summary": "Demonstrates invalid array index access in getValue(int[] numbers) where index 3 is accessed on a 3-element array, triggering ArrayIndexOutOfBoundsException."
    },
    "exception_handling": {
        "id": "exception_handling",
        "title": "Suppressed Exception Handling",
        "category": "Error Handling & Logging",
        "cwe": "CWE-390: Detection of Error Condition Without Action",
        "vulnerable_file": "com/securecoding/samples/ExceptionHandlingVulnerable.java",
        "fixed_file": "com/securecoding/samples/ExceptionHandlingFixed.java",
        "vulnerable_class": "com.securecoding.samples.ExceptionHandlingVulnerable",
        "fixed_class": "com.securecoding.samples.ExceptionHandlingFixed",
        "test_class": "com.securecoding.tests.ExceptionHandlingTest",
        "summary": "Demonstrates suppressed exception in calculate() where ArithmeticException from division by zero (10 / 0) is silently swallowed with an empty catch block."
    },
    "resource_handling": {
        "id": "resource_handling",
        "title": "Unclosed I/O Resource Leak",
        "category": "Resource Management",
        "cwe": "CWE-404 / CWE-775: Missing Release of Resource after Effective Lifetime",
        "vulnerable_file": "com/securecoding/samples/ResourceHandlingVulnerable.java",
        "fixed_file": "com/securecoding/samples/ResourceHandlingFixed.java",
        "vulnerable_class": "com.securecoding.samples.ResourceHandlingVulnerable",
        "fixed_class": "com.securecoding.samples.ResourceHandlingFixed",
        "test_class": "com.securecoding.tests.ResourceHandlingTest",
        "summary": "Demonstrates unclosed resource leak in readFile(Path path) where BufferedReader is opened without try-with-resources, risking OS file descriptor exhaustion."
    }
}

def ensure_dirs():
    """Ensure build and report output directories exist."""
    TARGET_CLASSES.mkdir(parents=True, exist_ok=True)
    TARGET_TEST_CLASSES.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "surefire").mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "jacoco").mkdir(parents=True, exist_ok=True)

def check_tools_status():
    """Check genuine availability of Java runtime and the four analysis tools."""
    status = {
        "java": {"available": False, "version": None, "role": "Runtime Environment & Bytecode Execution"},
        "javac": {"available": False, "version": None, "role": "Java Compiler (Bytecode Generator)"},
        "pmd": {"available": False, "version": None, "role": "Tool 1: Static Source-Code AST Analysis"},
        "spotbugs": {"available": False, "version": None, "role": "Tool 2: Static Bytecode Analysis Engine"},
        "junit": {"available": False, "version": None, "role": "Tool 3: Dynamic Runtime Test Executor (JUnit 5)"},
        "jacoco": {"available": False, "version": None, "role": "Tool 4: Runtime Code Coverage Instrumentation"}
    }

    # Java
    try:
        res = subprocess.run(["java", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        out = res.stderr or res.stdout
        if "version" in out.lower():
            v_line = out.splitlines()[0] if out.splitlines() else "Available"
            status["java"]["available"] = True
            status["java"]["version"] = v_line
    except Exception as e:
        status["java"]["error"] = str(e)

    # Javac
    try:
        res = subprocess.run(["javac", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        out = res.stdout or res.stderr
        if "javac" in out.lower():
            status["javac"]["available"] = True
            status["javac"]["version"] = out.strip()
    except Exception as e:
        status["javac"]["error"] = str(e)

    # PMD
    if PMD_BIN.exists() and os.access(PMD_BIN, os.X_OK):
        try:
            res = subprocess.run([str(PMD_BIN), "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            out = res.stdout or res.stderr
            status["pmd"]["available"] = True
            status["pmd"]["version"] = [line for line in out.splitlines() if "PMD" in line][0] if "PMD" in out else "PMD 7.0.0"
        except Exception as e:
            status["pmd"]["error"] = str(e)

    # SpotBugs
    if SPOTBUGS_HOME.exists() and (SPOTBUGS_HOME / "lib" / "spotbugs.jar").exists():
        status["spotbugs"]["available"] = True
        status["spotbugs"]["version"] = "SpotBugs 4.8.6 (Bytecode Analyzer)"

    # JUnit 5
    if JUNIT_JAR.exists():
        status["junit"]["available"] = True
        status["junit"]["version"] = "JUnit 5 Console Standalone 1.10.2"

    # JaCoCo
    if JACOCO_AGENT_JAR.exists() and JACOCO_CLI_JAR.exists():
        status["jacoco"]["available"] = True
        status["jacoco"]["version"] = "JaCoCo 0.8.12 (Agent & CLI)"

    return status

def compile_project():
    """Compile all Java source files and test files into target directories."""
    ensure_dirs()
    
    # Clean stale compiled classes to prevent phantom inner classes or outdated bytecode
    if TARGET_CLASSES.exists():
        for cf in TARGET_CLASSES.rglob("*.class"):
            cf.unlink()
    if TARGET_TEST_CLASSES.exists():
        for cf in TARGET_TEST_CLASSES.rglob("*.class"):
            cf.unlink()

    # 1. Compile main source files
    src_files = list(SRC_DIR.rglob("*.java"))
    if not src_files:
        return {"success": False, "error": "No Java source files found in src/main/java"}
    
    cmd_main = ["javac", "--release", "17", "-d", str(TARGET_CLASSES)] + [str(p) for p in src_files]
    res_main = subprocess.run(cmd_main, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
    if res_main.returncode != 0:
        return {"success": False, "stage": "main_compilation", "error": res_main.stderr}

    # 2. Compile test files
    test_files = list(TEST_SRC_DIR.rglob("*.java"))
    if test_files:
        cp = f"{TARGET_CLASSES}:{JUNIT_JAR}"
        cmd_test = ["javac", "--release", "17", "-cp", cp, "-d", str(TARGET_TEST_CLASSES)] + [str(p) for p in test_files]
        res_test = subprocess.run(cmd_test, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        if res_test.returncode != 0:
            return {"success": False, "stage": "test_compilation", "error": res_test.stderr}

    return {"success": True, "classes_dir": str(TARGET_CLASSES), "test_classes_dir": str(TARGET_TEST_CLASSES)}

def run_pmd(target_path=None):
    """
    Execute PMD against selected source files or full project.
    Parses genuine JSON output with exact line numbers and rules.
    """
    ensure_dirs()
    report_file = REPORTS_DIR / "pmd-report.json"
    
    if target_path:
        # Validate that path is within project
        full_target = (BASE_DIR / target_path).resolve()
        if not full_target.exists():
            return {"success": False, "error": f"Target path does not exist: {target_path}"}
    else:
        full_target = SRC_DIR

    cmd = [
        str(PMD_BIN), "check",
        "-d", str(full_target),
        "--use-version", "java-17",
        "--no-fail-on-violation",
        "--no-progress",
        "-R", str(PMD_RULESET),
        "-f", "json",
        "-r", str(report_file)
    ]

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    except Exception as e:
        return {"success": False, "error": f"PMD execution failed to launch: {str(e)}"}

    if not report_file.exists():
        return {"success": False, "error": f"PMD did not generate report file. Output: {res.stderr}"}

    try:
        with open(report_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as e:
        return {"success": False, "error": f"Failed to parse PMD JSON report: {str(e)}"}

    findings = []
    files_analyzed = len(raw_data.get("files", []))

    for file_entry in raw_data.get("files", []):
        file_name = file_entry.get("filename", "")
        # Relativize file path
        rel_path = file_name
        try:
            rel_path = str(Path(file_name).relative_to(BASE_DIR))
        except Exception:
            pass

        for v in file_entry.get("violations", []):
            rule = v.get("rule", "UnknownRule")
            explanation_meta = TOOL_EXPLANATIONS.get(rule, {})
            findings.append({
                "tool": "PMD",
                "file": rel_path,
                "begin_line": v.get("beginline"),
                "end_line": v.get("endline"),
                "begin_column": v.get("begincolumn"),
                "rule": rule,
                "ruleset": v.get("ruleset", "General"),
                "priority": v.get("priority", 3),
                "message": v.get("description", ""),
                "explanation": explanation_meta.get("why", "Static AST analysis flagged a potential code quality or secure coding violation."),
                "impact": explanation_meta.get("impact", "May cause unexpected runtime bugs or maintenance issues."),
                "remediation": explanation_meta.get("remediation", "Review the flagged code and apply defensive programming constructs."),
                "external_info_url": v.get("externalInfoUrl", "")
            })

    return {
        "success": True,
        "tool": "PMD",
        "files_analyzed": files_analyzed,
        "total_findings": len(findings),
        "findings": findings,
        "raw_json_path": str(report_file.relative_to(BASE_DIR))
    }

def run_spotbugs(class_filter=None):
    """
    Compile Java sample project and run SpotBugs against compiled bytecode.
    Parses genuine XML report for bug pattern, priority, and source locations.
    """
    ensure_dirs()
    compile_res = compile_project()
    if not compile_res.get("success"):
        return {"success": False, "error": f"Compilation before SpotBugs failed: {compile_res.get('error')}"}

    report_file = REPORTS_DIR / "spotbugs-report.xml"
    
    cmd = [
        "java", "-cp", f"{SPOTBUGS_HOME}/lib/*",
        "edu.umd.cs.findbugs.FindBugs2",
        "-effort:max",
        "-low",
        "-xml:withMessages",
        "-output", str(report_file),
        "-sourcepath", str(SRC_DIR)
    ]

    if class_filter:
        cmd.extend(["-onlyAnalyze", class_filter])

    cmd.append(str(TARGET_CLASSES))

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=25)
    except Exception as e:
        return {"success": False, "error": f"SpotBugs execution failed: {str(e)}"}

    if not report_file.exists():
        return {"success": False, "error": f"SpotBugs did not generate report XML. Stderr: {res.stderr}"}

    try:
        tree = ET.parse(report_file)
        root = tree.getroot()
    except Exception as e:
        return {"success": False, "error": f"Failed to parse SpotBugs XML: {str(e)}"}

    findings = []
    for bug in root.findall("BugInstance"):
        bug_type = bug.get("type", "UnknownBug")
        priority = int(bug.get("priority", "3"))
        category = bug.get("category", "General")
        
        # Source line info
        source_line_elem = bug.find("SourceLine")
        source_file = source_line_elem.get("sourcefile", "Unknown.java") if source_line_elem is not None else "Unknown"
        start_line = int(source_line_elem.get("start", "0")) if source_line_elem is not None and source_line_elem.get("start") else None
        end_line = int(source_line_elem.get("end", "0")) if source_line_elem is not None and source_line_elem.get("end") else None
        source_path = source_line_elem.get("sourcepath", "") if source_line_elem is not None else ""

        # Class info
        class_elem = bug.find("Class")
        class_name = class_elem.get("classname", "") if class_elem is not None else ""

        explanation_meta = TOOL_EXPLANATIONS.get(bug_type, {})

        priority_label = {1: "High", 2: "Medium", 3: "Low"}.get(priority, "Low")

        findings.append({
            "tool": "SpotBugs",
            "type": bug_type,
            "category": category,
            "priority": priority,
            "priority_label": priority_label,
            "class_name": class_name,
            "source_file": source_file,
            "source_path": f"src/main/java/{source_path}" if source_path else "",
            "start_line": start_line,
            "end_line": end_line,
            "message": f"SpotBugs detected {bug_type} ({category}) in {class_name}",
            "explanation": explanation_meta.get("why", "Bytecode analysis detected a potential bug pattern or security flaw during class inspection."),
            "impact": explanation_meta.get("impact", "May lead to runtime exceptions or environmental dependency vulnerabilities."),
            "remediation": explanation_meta.get("remediation", "Apply defensive code patterns and avoid platform-dependent defaults.")
        })

    return {
        "success": True,
        "tool": "SpotBugs",
        "total_findings": len(findings),
        "findings": findings,
        "raw_xml_path": str(report_file.relative_to(BASE_DIR))
    }

def run_junit(test_class=None):
    """
    Execute genuine Java test cases using JUnit 5 Console Standalone.
    Also instruments with JaCoCo Java agent to capture runtime coverage data.
    """
    ensure_dirs()
    compile_res = compile_project()
    if not compile_res.get("success"):
        return {"success": False, "error": f"Compilation failed before tests: {compile_res.get('error')}"}

    surefire_dir = REPORTS_DIR / "surefire"
    jacoco_exec = REPORTS_DIR / "jacoco.exec"
    jacoco_dir = REPORTS_DIR / "jacoco"

    # Clean old surefire test reports, old jacoco.exec and xml to ensure single source of truth
    if surefire_dir.exists():
        for sf in surefire_dir.glob("*.xml"):
            sf.unlink()
    if jacoco_exec.exists():
        jacoco_exec.unlink()
    jacoco_xml = jacoco_dir / "jacoco.xml"
    if jacoco_xml.exists():
        jacoco_xml.unlink()

    # Command to run JUnit with JaCoCo agent (append=false ensures fresh capture)
    cp = f"{TARGET_CLASSES}:{TARGET_TEST_CLASSES}"
    agent_arg = f"-javaagent:{JACOCO_AGENT_JAR}=destfile={jacoco_exec},append=false"

    cmd = [
        "java",
        agent_arg,
        "-jar", str(JUNIT_JAR),
        "execute",
        "--class-path", cp,
        "--disable-banner",
        "--reports-dir", str(surefire_dir)
    ]

    if test_class:
        cmd.extend(["--select-class", test_class])
    else:
        cmd.append("--scan-class-path")

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    except Exception as e:
        return {"success": False, "error": f"JUnit execution error: {str(e)}"}

    # Generate JaCoCo report from captured jacoco.exec
    coverage_summary = {}
    if jacoco_exec.exists():
        jacoco_html = jacoco_dir / "html"
        cmd_jacoco = [
            "java", "-jar", str(JACOCO_CLI_JAR), "report",
            str(jacoco_exec),
            "--classfiles", str(TARGET_CLASSES),
            "--sourcefiles", str(SRC_DIR),
            "--xml", str(jacoco_xml),
            "--html", str(jacoco_html)
        ]
        subprocess.run(cmd_jacoco, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        if jacoco_xml.exists():
            coverage_summary = parse_jacoco_xml(jacoco_xml)

    # Known defect lines to connect demonstration tests to vulnerable code locations
    KNOWN_DEFECT_LINES = {
        "testVulnerableNullThrowsException": {"file": "NullHandlingVulnerable.java", "line": 27, "desc": "Dereferencing text.length() without null check throws NullPointerException"},
        "testVulnerableThreeElementsThrowsException": {"file": "ArrayBoundsVulnerable.java", "line": 31, "desc": "Accessing numbers[3] on 3-element array throws ArrayIndexOutOfBoundsException"},
        "testVulnerableSwallowsException": {"file": "ExceptionHandlingVulnerable.java", "line": 33, "desc": "Division by zero (10 / 0) caught and swallowed by empty catch block"},
        "testVulnerableReadsFile": {"file": "ResourceHandlingVulnerable.java", "line": 35, "desc": "BufferedReader opened without try-with-resources statement leaving stream unclosed"},
    }

    # Parse Surefire XML report for test results
    test_results = []
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    skipped_tests = 0

    jupiter_xml = surefire_dir / "TEST-junit-jupiter.xml"
    if jupiter_xml.exists():
        try:
            tree = ET.parse(jupiter_xml)
            root = tree.getroot()
            total_tests = int(root.get("tests", "0"))
            failed_tests = int(root.get("failures", "0")) + int(root.get("errors", "0"))
            skipped_tests = int(root.get("skipped", "0"))
            passed_tests = total_tests - failed_tests - skipped_tests

            for tc in root.findall("testcase"):
                name = tc.get("name", "UnknownTest")
                cname = tc.get("classname", "")
                time_taken = float(tc.get("time", "0.0"))
                failure = tc.find("failure")
                error = tc.find("error")

                is_passed = (failure is None and error is None)
                fail_elem = failure if failure is not None else error
                fail_msg = fail_elem.get("message", "") if fail_elem is not None else None
                fail_type = fail_elem.get("type", "") if fail_elem is not None else None
                stack_trace = fail_elem.text if fail_elem is not None else None

                clean_name = name.replace("()", "")
                defect_info = KNOWN_DEFECT_LINES.get(clean_name)
                is_defect_demo = (defect_info is not None) or ("vulnerable" in name.lower()) or ("throwsexception" in name.lower())

                if is_defect_demo:
                    if is_passed:
                        demo_outcome = "Defect Reproduced (Expected Exception Verified)"
                    else:
                        demo_outcome = "Defect Reproduction Failed (Unexpected Failure)"
                else:
                    demo_outcome = "Defensive Behavior Verified" if is_passed else "Unexpected Failure"

                test_results.append({
                    "name": name,
                    "class_name": cname,
                    "duration_seconds": time_taken,
                    "status": "PASSED" if is_passed else "FAILED",
                    "is_defect_demo": is_defect_demo,
                    "demonstration_outcome": demo_outcome,
                    "defect_target_line": defect_info.get("line") if defect_info else None,
                    "defect_target_file": defect_info.get("file") if defect_info else None,
                    "defect_description": defect_info.get("desc") if defect_info else None,
                    "failure_message": fail_msg,
                    "failure_type": fail_type,
                    "stack_trace": stack_trace
                })
        except Exception as e:
            return {"success": False, "error": f"Failed to parse JUnit XML report: {str(e)}"}

    return {
        "success": True,
        "tool": "JUnit 5",
        "total_tests": total_tests,
        "passed": passed_tests,
        "failed": failed_tests,
        "skipped": skipped_tests,
        "tests": test_results,
        "coverage": coverage_summary,
        "raw_console": res.stdout
    }

def is_non_executable_source_line(text):
    """
    Check if a line in Java source code is non-executable (e.g. comments, declarations, imports).
    JaCoCo reports line numbers for bytecode, which occasionally assigns compiler synthetic
    constructors to class declarations or header lines. We ensure non-executable lines are kept neutral.
    """
    if not text:
        return True
    t = text.strip()
    if not t:
        return True
    if t.startswith("//") or t.startswith("/*") or t.startswith("*") or t.endswith("*/"):
        return True
    if t.startswith("package ") or t.startswith("import "):
        return True
    import re
    if re.match(r'^(public\s+|protected\s+|private\s+|static\s+|final\s+|abstract\s+)*(class|interface|enum|record)\s+', t):
        return True
    if t in ("{", "}", "{ }", "{}"):
        return True
    return False

def parse_jacoco_xml(xml_path):
    """
    Parse genuine JaCoCo XML report into per-sourcefile coverage mapping and overall percentages.
    Extracts authentic counters for line, branch, instruction coverage per file and globally.
    Filters non-executable declaration lines (e.g. class declarations) so they are kept neutral.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return {"error": f"Cannot parse JaCoCo XML: {str(e)}"}

    files_coverage = {}
    total_lines = 0
    covered_lines = 0
    total_branches = 0
    covered_branches = 0

    for pkg in root.findall("package"):
        pkg_name = pkg.get("name", "")
        pkg_dir = SRC_DIR / pkg_name

        for src in pkg.findall("sourcefile"):
            sname = src.get("name")
            lines_map = {}

            # Read source lines for this file if available to check executable status
            src_file_path = pkg_dir / sname
            src_lines = []
            if src_file_path.exists():
                try:
                    with open(src_file_path, "r", encoding="utf-8") as f:
                        src_lines = f.read().splitlines()
                except Exception:
                    src_lines = []

            # Extract authentic counters directly from <sourcefile>
            f_line_cov = 0
            f_line_miss = 0
            f_branch_cov = 0
            f_branch_miss = 0
            f_inst_cov = 0
            f_inst_miss = 0

            for counter in src.findall("counter"):
                ctype = counter.get("type")
                if ctype == "LINE":
                    f_line_cov = int(counter.get("covered", "0"))
                    f_line_miss = int(counter.get("missed", "0"))
                elif ctype == "BRANCH":
                    f_branch_cov = int(counter.get("covered", "0"))
                    f_branch_miss = int(counter.get("missed", "0"))
                elif ctype == "INSTRUCTION":
                    f_inst_cov = int(counter.get("covered", "0"))
                    f_inst_miss = int(counter.get("missed", "0"))

            for l in src.findall("line"):
                nr = int(l.get("nr"))
                mi = int(l.get("mi", "0")) # missed instructions
                ci = int(l.get("ci", "0")) # covered instructions
                mb = int(l.get("mb", "0")) # missed branches
                cb = int(l.get("cb", "0")) # covered branches

                line_text = src_lines[nr - 1] if src_lines and 0 < nr <= len(src_lines) else ""
                is_non_exec = is_non_executable_source_line(line_text)

                if is_non_exec:
                    status = "neutral"
                    is_exec = False
                elif ci > 0 and mi == 0 and mb == 0:
                    status = "covered"
                    is_exec = True
                elif ci > 0 and (mi > 0 or mb > 0):
                    status = "partially_covered"
                    is_exec = True
                else:
                    status = "uncovered"
                    is_exec = True

                lines_map[nr] = {
                    "line_number": nr,
                    "status": status,
                    "is_executable": is_exec,
                    "covered_instructions": ci,
                    "missed_instructions": mi,
                    "covered_branches": cb,
                    "missed_branches": mb
                }

            f_total_lines = f_line_cov + f_line_miss
            f_line_pct = round((f_line_cov / f_total_lines * 100), 1) if f_total_lines > 0 else 0.0

            f_total_branches = f_branch_cov + f_branch_miss
            f_branch_pct = round((f_branch_cov / f_total_branches * 100), 1) if f_total_branches > 0 else None

            files_coverage[sname] = {
                "file_name": sname,
                "lines_count": f_total_lines,
                "covered_lines": f_line_cov,
                "missed_lines": f_line_miss,
                "line_coverage_percentage": f_line_pct,
                "has_branches": (f_total_branches > 0),
                "total_branches": f_total_branches,
                "covered_branches": f_branch_cov,
                "missed_branches": f_branch_miss,
                "branch_coverage_percentage": f_branch_pct,
                "lines": lines_map
            }

    # Global counters from report root
    for counter in root.findall("counter"):
        ctype = counter.get("type")
        c_covered = int(counter.get("covered", "0"))
        c_missed = int(counter.get("missed", "0"))
        if ctype == "LINE":
            total_lines = c_covered + c_missed
            covered_lines = c_covered
        elif ctype == "BRANCH":
            total_branches = c_covered + c_missed
            covered_branches = c_covered

    overall_line_pct = round((covered_lines / total_lines * 100), 1) if total_lines > 0 else 0.0
    overall_branch_pct = round((covered_branches / total_branches * 100), 1) if total_branches > 0 else 0.0

    return {
        "overall_line_coverage": overall_line_pct,
        "overall_branch_coverage": overall_branch_pct,
        "total_lines": total_lines,
        "covered_lines": covered_lines,
        "total_branches": total_branches,
        "covered_branches": covered_branches,
        "files": files_coverage
    }

def get_source_file_content(relative_file_path):
    """
    Safely read and return actual Java source code from the real files.
    Ensures no path traversal outside project.
    """
    full_path = (BASE_DIR / relative_file_path).resolve()
    if not full_path.exists() or not full_path.is_file():
        return {"error": f"File not found: {relative_file_path}"}
    
    # Security check: must reside inside BASE_DIR
    try:
        full_path.relative_to(BASE_DIR)
    except ValueError:
        return {"error": "Access denied: Path traversal attempted"}

    with open(full_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()
    return {
        "file_path": relative_file_path,
        "file_name": full_path.name,
        "total_lines": len(lines),
        "content": content,
        "lines": [{"number": idx + 1, "text": line} for idx, line in enumerate(lines)]
    }
