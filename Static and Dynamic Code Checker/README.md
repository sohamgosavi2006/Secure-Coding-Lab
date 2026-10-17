# JavaCodeCheck — Interactive Static & Runtime Code Analysis Lab

**Course:** B.Tech Minor Degree in Cyber Security (Secure Coding)  
**Project:** Static Analysis, Bytecode Inspection, Runtime Unit Testing, and Code Coverage  
**Tools:** PMD 7.0.0, SpotBugs 4.8.6 (ASM 9.11), JUnit 5 (Jupiter 1.10.2), JaCoCo 0.8.12  
**Platform:** Java 25 (LTS, bytecode target 17), Python 3 Flask, HTML5/CSS3/Vanilla JS  
**Environment:** Localhost sandbox (127.0.0.1:5051 / 127.0.0.1:5050)

---

## 1. Project Objective & Scope

**JavaCodeCheck** is an interactive, educational secure coding laboratory built to demonstrate the concepts of:
1. **Static Source Analysis** (AST pattern matching on source files)
2. **Static Bytecode Analysis** (class structure and control-flow graph inspection)
3. **Dynamic Runtime Testing** (behavior verification, exception demonstration, input handling)
4. **Runtime Code Coverage** (line and branch execution measurement)
5. **Defensive Secure Coding Remediation** (side-by-side comparison of vulnerable vs. corrected implementations)

This is an educational minimum viable product (MVP) built for college academic evaluation, viva presentation, and practical demonstration.

---

## 2. The Four Analysis Tools & Their Roles

| Tool | Category | Analysis Target | Role & Methodology |
|---|---|---|---|
| **PMD (v7.0.0)** | Static Analysis | Source Code (`.java`) | Parses Java source files into an **Abstract Syntax Tree (AST)** without compilation. Evaluates XPath and Java rules against AST nodes to detect empty catch blocks, unclosed I/O resources, and code smells. |
| **SpotBugs (v4.8.6)** | Static Analysis | Compiled Bytecode (`.class`) | Uses **ObjectWeb ASM 9.11** to inspect compiled Java bytecode. Traverses Control Flow Graphs (CFGs) and dataflow states to identify null dereferences, platform encoding dependencies, and subtle bugs. |
| **JUnit 5 (v1.10.2)** | Dynamic Testing | Compiled Test Classes | Executes actual Java unit tests inside the Java Virtual Machine (JVM). Validates expected vs. actual behavior, tests boundary conditions, and demonstrates real runtime exceptions (e.g., `ArrayIndexOutOfBoundsException`, `NullPointerException`). |
| **JaCoCo (v0.8.12)** | Dynamic Coverage | JVM Bytecode Execution | Operates via a **Java Agent** (`-javaagent`) that injects execution probes into bytecode on-the-fly during test runs. Measures exact line and branch coverage percentages and identifies unexercised paths. |

> [!IMPORTANT]
> **Coverage vs. Correctness:** JaCoCo indicates which code was exercised during a specific test run. High coverage does **NOT** prove code is secure or defect-free.

---

## 3. Directory Structure

```text
Static and Dynamic Code Checker/
├── config/
│   └── pmd-ruleset.xml         # Curated PMD ruleset targeting security & error-prone patterns
├── src/
│   ├── main/java/com/securecoding/samples/
│   │   ├── NullHandlingVulnerable.java       # Flaw: Unchecked null dereference
│   │   ├── NullHandlingFixed.java            # Fix: Defensive null validation & safe fallback
│   │   ├── ArrayBoundsVulnerable.java        # Flaw: Off-by-one boundary flaw (index <= length)
│   │   ├── ArrayBoundsFixed.java             # Fix: Strict 0 <= index < length validation
│   │   ├── ExceptionHandlingVulnerable.java  # Flaw: Empty catch block silently hides failure
│   │   ├── ExceptionHandlingFixed.java       # Fix: Specific catch, logging & valid TCP range
│   │   ├── ResourceHandlingVulnerable.java   # Flaw: Reader opened without try-with-resources
│   │   └── ResourceHandlingFixed.java        # Fix: Java 7+ try-with-resources auto-cleanup
│   └── test/java/com/securecoding/tests/
│       ├── NullHandlingTest.java             # JUnit 5 suite testing both versions
│       ├── ArrayBoundsTest.java              # JUnit 5 suite testing both versions
│       ├── ExceptionHandlingTest.java        # JUnit 5 suite testing both versions
│       └── ResourceHandlingTest.java         # JUnit 5 suite testing both versions
├── tools/
│   ├── junit-platform-console-standalone.jar # JUnit 5 console runner
│   ├── jacocoagent.jar                       # JaCoCo runtime instrumentation agent
│   ├── jacococli.jar                         # JaCoCo report generator CLI
│   ├── pmd-bin-7.0.0/                        # Standalone PMD 7 distribution
│   └── spotbugs-4.8.6/                       # Standalone SpotBugs distribution (with ASM 9.11)
├── reports/                                  # Machine-readable reports (JSON/XML)
│   ├── pmd-report.json                       # PMD output report
│   ├── spotbugs-report.xml                   # SpotBugs output report
│   ├── surefire/                             # JUnit Surefire XML test outcomes
│   └── jacoco/                               # JaCoCo XML & HTML coverage data
├── templates/
│   └── index.html                            # Educational dashboard UI
├── static/
│   ├── style.css                             # Design system (warm off-white & serif)
│   └── app.js                                # Interactive 8-step guided demo engine
├── runner.py                                 # Process execution & report parsing engine
├── app.py                                    # Standalone Flask server entrypoint
├── pom.xml                                   # Standard Maven build descriptor
└── README.md                                 # Technical documentation
```

---

## 4. Quick Start (Running Locally)

### Prerequisites
- **Java 17+** installed (`java -version`, `javac -version`) — tested with Java 25 LTS
- **Python 3.9+** installed (`python3 --version`)

### Step 1: Navigate to Project Directory
```bash
cd "Static and Dynamic Code Checker"
```

### Step 2: Run the Web Application
```bash
python3 app.py
```

### Step 3: Open in Browser
Open your web browser and navigate to:
```text
http://127.0.0.1:5051
```
(Or run the root master portal on `http://127.0.0.1:5050` to access both SQL Injection and JavaCodeCheck).

---

## 5. The 4 Predefined Educational Scenarios

### Scenario 1: Null Handling (CWE-476)
- **Vulnerable:** `NullHandlingVulnerable.java` calls `customer.getName().trim().toUpperCase()` without checking for null.
- **Defect:** Triggers an unchecked `NullPointerException` if customer or name is null.
- **Fixed:** `NullHandlingFixed.java` applies defensive checks with `"ANONYMOUS"` and `"UNNAMED_CUSTOMER"` safe fallbacks.
- **Tests:** `NullHandlingTest.java` verifies that null inputs trigger expected exception on vulnerable code and produce graceful fallbacks on fixed code.

### Scenario 2: Array Boundaries (CWE-129 / CWE-193)
- **Vulnerable:** `ArrayBoundsVulnerable.java` checks `if (index <= items.length)` instead of `< items.length`.
- **Defect:** Accessing index 4 in an array of size 4 triggers `ArrayIndexOutOfBoundsException`.
- **Fixed:** `ArrayBoundsFixed.java` enforces `0 <= index < items.length` and raises informative `IndexOutOfBoundsException`.
- **Tests:** `ArrayBoundsTest.java` validates off-by-one behavior and boundary enforcement.

### Scenario 3: Exception Handling (CWE-390 / CWE-391)
- **Vulnerable:** `ExceptionHandlingVulnerable.java` contains an empty `catch (Exception e) {}` block.
- **Defect:** Silently suppresses invalid non-numeric port strings, leaving the system in a stale state.
- **Fixed:** `ExceptionHandlingFixed.java` catches `NumberFormatException`, logs diagnostic warnings, validates port range (1–65535), and uses default port fallback.
- **Tests:** `ExceptionHandlingTest.java` verifies silent suppression versus structured recovery.

### Scenario 4: Resource Handling (CWE-404 / CWE-775)
- **Vulnerable:** `ResourceHandlingVulnerable.java` opens `InputStream` and `BufferedReader` without try-with-resources.
- **Defect:** An exception during reading bypasses `close()`, leaking file descriptors and memory buffers.
- **Fixed:** `ResourceHandlingFixed.java` uses Java 7+ `try-with-resources` (`AutoCloseable`).
- **Tests:** `ResourceHandlingTest.java` validates stream lifecycle and error handling.

---

## 6. How Findings and Coverage are Parsed

1. **PMD Execution & Parsing:**
   - Invokes: `pmd check -d <file> --use-version java-17 -R config/pmd-ruleset.xml -f json`
   - Parses: JSON `violations` array into line numbers, priority (1–5), rule names, and explanations.
   - UI: Highlights the exact source code line in the code viewer upon clicking a finding.

2. **SpotBugs Execution & Parsing:**
   - Compiles source files using `javac --release 17`.
   - Invokes: `edu.umd.cs.findbugs.FindBugs2 -effort:max -low -xml:withMessages <target/classes>`
   - Parses: XML `<BugInstance>` elements into bug pattern codes, priority levels, and line ranges.

3. **JUnit 5 Execution & Parsing:**
   - Invokes: `junit-platform-console-standalone.jar execute --class-path <classes>:<test-classes> --reports-dir reports/surefire`
   - Parses: `TEST-junit-jupiter.xml` into passed/failed counts, execution times, failure messages, and stack traces.

4. **JaCoCo Coverage Generation & Mapping:**
   - Instruments test execution via `-javaagent:tools/jacocoagent.jar=destfile=reports/jacoco.exec`.
   - Generates XML report using `jacococli.jar report`.
   - Parses line counters (`ci` covered instructions, `mi` missed instructions).
   - UI: Highlights lines dynamically in the source viewer (Green = Covered, Yellow = Partially Covered, Red = Uncovered).

---

## 7. Known Limitations of the MVP

1. **Predefined Scope:** The lab intentionally focuses on four clear, reproducible educational scenarios designed for viva explanation rather than arbitrary multi-module enterprise codebases.
2. **Localhost Execution:** Designed exclusively for local academic demonstration with fixed allowlisted commands; does not accept arbitrary file uploads or execute unvalidated user scripts.
3. **Java Version Interoperability:** Uses Java 25 runtime targeting Java 17 bytecode with ASM 9.11 to maintain compatibility across all four tools.
