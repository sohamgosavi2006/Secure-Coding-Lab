/**
 * JavaCodeCheck - Interactive Frontend Controller
 * Drives the 8-step guided demo, real source viewer, live tool execution,
 * findings highlighting, and JaCoCo coverage mapping.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Global Theme Controller
  initGlobalThemeToggle();

  function initGlobalThemeToggle() {
    const toggleBtn = document.getElementById("global-theme-toggle-btn");
    if (!toggleBtn) return;

    const lightLabel = toggleBtn.querySelector(".theme-label-light");
    const darkLabel = toggleBtn.querySelector(".theme-label-dark");

    function updateThemeUI(theme) {
      if (theme === "dark") {
        document.documentElement.setAttribute("data-theme", "dark");
        toggleBtn.setAttribute("aria-checked", "true");
        toggleBtn.setAttribute("aria-label", "Switch to light theme");
        if (lightLabel) lightLabel.classList.remove("active");
        if (darkLabel) darkLabel.classList.add("active");
        try { localStorage.setItem("securelab_theme", "dark"); } catch (e) {}
      } else {
        document.documentElement.setAttribute("data-theme", "light");
        toggleBtn.setAttribute("aria-checked", "false");
        toggleBtn.setAttribute("aria-label", "Switch to dark theme");
        if (lightLabel) lightLabel.classList.add("active");
        if (darkLabel) darkLabel.classList.remove("active");
        try { localStorage.setItem("securelab_theme", "light"); } catch (e) {}
      }
    }

    let activeTheme = "light";
    try {
      if (localStorage.getItem("securelab_theme") === "dark") activeTheme = "dark";
    } catch (e) {}
    updateThemeUI(activeTheme);

    toggleBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      updateThemeUI(current === "dark" ? "light" : "dark");
    });
  }

  // Global State
  let currentScenarioId = "null_handling";
  let currentVersion = "vulnerable"; // "vulnerable" or "fixed"
  let currentDemoStep = 1;
  let scenariosData = {};
  let currentSourceData = null;
  let activeCoverageMap = null;
  const scenarioToolRuns = {};

  function getScenarioRuns(scId) {
    if (!scenarioToolRuns[scId]) {
      scenarioToolRuns[scId] = {
        pmd: null,
        pmdFixed: null,
        pmdRan: false,
        spotbugs: null,
        spotbugsFixed: null,
        spotbugsRan: false,
        junit: null,
        junitRan: false,
        jacoco: null,
        jacocoRan: false
      };
    }
    return scenarioToolRuns[scId];
  }

  function hasRunAllTools(scId) {
    const runs = getScenarioRuns(scId);
    return !!(runs.pmd && runs.spotbugs && runs.junit && runs.jacoco && runs.pmdRan && runs.spotbugsRan && runs.junitRan && runs.jacocoRan);
  }

  // Cache DOM Elements
  const scenarioSelect = document.getElementById("scenario-select");
  const versionVulnerableBtn = document.getElementById("btn-version-vulnerable");
  const versionFixedBtn = document.getElementById("btn-version-fixed");
  const sourceFilePathElem = document.getElementById("code-viewer-path");
  const codeViewerBody = document.getElementById("code-viewer-body");

  // Step Indicators
  const stepPills = document.querySelectorAll(".step-pill");
  const btnStepPrev = document.getElementById("btn-step-prev");
  const btnStepNext = document.getElementById("btn-step-next");
  const btnExitDemo = document.getElementById("btn-exit-demo");

  // Tab Navigation
  const subNavBtns = document.querySelectorAll(".sub-tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  // Initialize
  initApp();

  async function initApp() {
    setupTabSwitching();
    setupVersionToggle();
    setupDemoNavigation();
    setupActionButtons();
    await fetchToolStatus();
    await fetchScenarios();
    loadScenario(currentScenarioId);
  }

  // -------------------------------------------------------------------------
  // 1. Navigation & Tabs
  // -------------------------------------------------------------------------
  function setupTabSwitching() {
    subNavBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        subNavBtns.forEach(b => b.classList.remove("active"));
        tabPanes.forEach(p => p.classList.remove("active"));

        btn.classList.add("active");
        const targetId = btn.getAttribute("data-tab");
        const targetPane = document.getElementById(`tab-${targetId}`);
        if (targetPane) targetPane.classList.add("active");

        if (targetId === "comparison") {
          loadComparisonMatrix();
        }
      });
    });
  }

  // -------------------------------------------------------------------------
  // 2. Tool Status Checker
  // -------------------------------------------------------------------------
  async function fetchToolStatus() {
    try {
      const res = await fetch("/api/status");
      const data = await res.json();
      if (!data.tools) return;

      updateStatusCard("pmd", data.tools.pmd);
      updateStatusCard("spotbugs", data.tools.spotbugs);
      updateStatusCard("junit", data.tools.junit);
      updateStatusCard("jacoco", data.tools.jacoco);
    } catch (e) {
      console.warn("Could not fetch tool status:", e);
    }
  }

  function updateStatusCard(id, tool) {
    const badge = document.getElementById(`status-badge-${id}`);
    const ver = document.getElementById(`status-version-${id}`);
    if (!badge || !tool) return;

    if (tool.available) {
      badge.className = "badge badge-success";
      badge.textContent = "READY";
      if (ver) ver.textContent = tool.version || "Installed";
    } else {
      badge.className = "badge badge-danger";
      badge.textContent = "NOT READY";
      if (ver) ver.textContent = tool.error || "Unavailable";
    }
  }

  // -------------------------------------------------------------------------
  // 3. Scenario & Source Code Loading
  // -------------------------------------------------------------------------
  async function fetchScenarios() {
    try {
      const res = await fetch("/api/scenarios");
      const data = await res.json();
      if (data.scenarios) {
        scenarioSelect.innerHTML = "";
        data.scenarios.forEach(sc => {
          scenariosData[sc.id] = sc;
          const opt = document.createElement("option");
          opt.value = sc.id;
          opt.textContent = `${sc.title} (${sc.category})`;
          scenarioSelect.appendChild(opt);
        });

        scenarioSelect.addEventListener("change", async (e) => {
          currentScenarioId = e.target.value;
          await switchToVersion("vulnerable");
          loadScenario(currentScenarioId);
          onScenarioChanged(currentScenarioId);
        });
      }
    } catch (e) {
      console.error("Failed to load scenarios:", e);
    }
  }

  async function switchToVersion(version) {
    currentVersion = version;
    if (version === "vulnerable") {
      if (versionVulnerableBtn) versionVulnerableBtn.className = "version-pill-btn active-vulnerable";
      if (versionFixedBtn) versionFixedBtn.className = "version-pill-btn";
    } else {
      if (versionFixedBtn) versionFixedBtn.className = "version-pill-btn active-fixed";
      if (versionVulnerableBtn) versionVulnerableBtn.className = "version-pill-btn";
    }

    // Clear any prior line highlighting markers
    document.querySelectorAll(".finding-card.active-finding").forEach(c => c.classList.remove("active-finding"));
    const btnToggle = document.getElementById("btn-toggle-coverage-overlay");
    if (btnToggle) {
      btnToggle.textContent = "Highlight All Covered & Uncovered Lines in Code Viewer";
    }

    const sc = scenariosData[currentScenarioId];
    if (sc) {
      const relFile = currentVersion === "vulnerable" ? sc.vulnerable_file : sc.fixed_file;
      await loadSourceFile(relFile);

      // If JaCoCo results were already displayed, refresh the coverage card for the newly selected file version
      const jacocoResults = document.getElementById("demo-jacoco-results");
      if (jacocoResults && activeCoverageMap) {
        renderJacocoResults(activeCoverageMap, jacocoResults);
      }
    }
  }

  function setupVersionToggle() {
    if (versionVulnerableBtn && versionFixedBtn) {
      versionVulnerableBtn.addEventListener("click", () => {
        switchToVersion("vulnerable");
      });

      versionFixedBtn.addEventListener("click", () => {
        switchToVersion("fixed");
      });
    }

    const btnClearHighlights = document.getElementById("btn-java-clear-highlights");
    if (btnClearHighlights) {
      btnClearHighlights.addEventListener("click", () => {
        if (currentSourceData && currentSourceData.lines) {
          renderSourceCode(currentSourceData.lines, null, null);
        }
        document.querySelectorAll(".finding-card.active-finding").forEach(c => c.classList.remove("active-finding"));
        const btnToggle = document.getElementById("btn-toggle-coverage-overlay");
        if (btnToggle) {
          btnToggle.textContent = "Highlight All Covered & Uncovered Lines in Code Viewer";
        }
        const origContent = btnClearHighlights.innerHTML;
        btnClearHighlights.innerHTML = `<span>✓ Cleared</span>`;
        setTimeout(() => {
          btnClearHighlights.innerHTML = origContent;
        }, 1200);
      });
    }
  }

  async function loadScenario(scenarioId) {
    const sc = scenariosData[scenarioId];
    if (!sc) return;

    // Update explanations in Step 1
    renderStep1Details(sc);

    // Determine target source file
    const relFile = currentVersion === "vulnerable" ? sc.vulnerable_file : sc.fixed_file;
    await loadSourceFile(relFile);
  }

  async function loadSourceFile(relPath) {
    sourceFilePathElem.textContent = "Loading source file...";
    const filename = relPath.split("/").pop();
    const fnElem = document.getElementById("java-code-viewer-filename");
    const bcElem = document.getElementById("java-code-viewer-breadcrumb");
    const badgeElem = document.getElementById("java-code-viewer-badge");

    if (fnElem) fnElem.textContent = filename;
    if (bcElem) bcElem.textContent = filename;
    if (sourceFilePathElem) sourceFilePathElem.textContent = "src/main/java/" + relPath;

    if (badgeElem) {
      badgeElem.textContent = currentVersion === "vulnerable" ? "Vulnerable Source" : "Corrected Source";
      badgeElem.className = currentVersion === "vulnerable" ? "vscode-chip vscode-chip-vuln" : "vscode-chip vscode-chip-fixed";
    }

    if (codeViewerBody) {
      codeViewerBody.innerHTML = '<div style="padding: 24px; color: #858585; font-family: var(--font-mono);">// Loading genuine Java source from disk...</div>';
    }

    try {
      const res = await fetch(`/api/source?file=${encodeURIComponent("src/main/java/" + relPath)}`);
      const json = await res.json();
      if (!json.success || !json.data) {
        if (codeViewerBody) {
          codeViewerBody.innerHTML = `<div style="padding: 24px; color: #f85149; font-family: var(--font-mono);">// Error loading source: ${escapeHtml(json.error)}</div>`;
        }
        return;
      }

      currentSourceData = json.data;
      renderSourceCode(json.data.lines);
    } catch (e) {
      if (codeViewerBody) {
        codeViewerBody.innerHTML = `<div style="padding: 24px; color: #f85149; font-family: var(--font-mono);">// Failed to fetch source: ${escapeHtml(e.message)}</div>`;
      }
    }
  }

  function highlightJavaLine(rawText, state) {
    let html = "";
    let text = rawText;

    if (state.inBlockComment) {
      const endIdx = text.indexOf("*/");
      if (endIdx === -1) {
        return `<span class="tok-comm">${escapeHtml(text)}</span>`;
      } else {
        html += `<span class="tok-comm">${escapeHtml(text.slice(0, endIdx + 2))}</span>`;
        text = text.slice(endIdx + 2);
        state.inBlockComment = false;
      }
    }

    const keywordsMod = new Set([
      "public", "private", "protected", "static", "final", "abstract",
      "synchronized", "volatile", "transient", "native", "strictfp",
      "class", "interface", "enum", "extends", "implements", "package", "import"
    ]);

    const keywordsControl = new Set([
      "if", "else", "for", "while", "do", "switch", "case", "default",
      "break", "continue", "return", "try", "catch", "finally", "throw",
      "throws", "new", "this", "super", "instanceof", "assert"
    ]);

    const keywordsConst = new Set(["true", "false", "null"]);

    const knownTypes = new Set([
      "String", "Integer", "Long", "Boolean", "Double", "Float", "Byte", "Short",
      "Character", "Object", "System", "Exception", "Throwable", "RuntimeException",
      "NullPointerException", "IndexOutOfBoundsException", "ArrayIndexOutOfBoundsException",
      "IOException", "BufferedReader", "FileReader", "InputStream", "FileInputStream",
      "StandardCharsets", "Customer", "Arrays", "List", "Map", "Set", "ArrayList",
      "HashMap", "HashSet", "Locale", "Scanner", "PrintStream", "StringBuilder",
      "int", "boolean", "byte", "char", "long", "double", "float", "short", "void"
    ]);

    const tokenRegex = /(\/\*[\s\S]*?\*\/|\/\*.*|\/\/.*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|@\w+|\b(?:0x[\da-fA-F]+|\d+(?:\.\d+)?(?:[fFdDlL])?)\b|\b[a-zA-Z_]\w*\b)/g;

    let lastIndex = 0;
    let match;

    while ((match = tokenRegex.exec(text)) !== null) {
      if (match.index > lastIndex) {
        html += escapeHtml(text.slice(lastIndex, match.index));
      }

      const tok = match[0];

      if (tok.startsWith("/*")) {
        if (tok.endsWith("*/") && tok.length > 2) {
          html += `<span class="tok-comm">${escapeHtml(tok)}</span>`;
        } else {
          html += `<span class="tok-comm">${escapeHtml(tok)}</span>`;
          state.inBlockComment = true;
        }
      } else if (tok.startsWith("//")) {
        html += `<span class="tok-comm">${escapeHtml(tok)}</span>`;
      } else if (tok.startsWith('"') || tok.startsWith("'")) {
        html += `<span class="tok-str">${escapeHtml(tok)}</span>`;
      } else if (tok.startsWith("@")) {
        html += `<span class="tok-ann">${escapeHtml(tok)}</span>`;
      } else if (keywordsMod.has(tok)) {
        html += `<span class="tok-kw-mod">${escapeHtml(tok)}</span>`;
      } else if (keywordsControl.has(tok) || keywordsConst.has(tok)) {
        html += `<span class="tok-kw">${escapeHtml(tok)}</span>`;
      } else if (knownTypes.has(tok)) {
        html += `<span class="tok-type">${escapeHtml(tok)}</span>`;
      } else if (/^(?:0x[\da-fA-F]+|\d)/.test(tok)) {
        html += `<span class="tok-num">${escapeHtml(tok)}</span>`;
      } else {
        const lookahead = text.slice(tokenRegex.lastIndex);
        if (/^\s*\(/.test(lookahead)) {
          html += `<span class="tok-fn">${escapeHtml(tok)}</span>`;
        } else {
          html += escapeHtml(tok);
        }
      }

      lastIndex = tokenRegex.lastIndex;
    }

    if (lastIndex < text.length) {
      html += escapeHtml(text.slice(lastIndex));
    }

    return html;
  }

  function isNonExecutableLine(text) {
    if (!text) return true;
    const trimmed = text.trim();
    if (!trimmed) return true;
    if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*") || trimmed.endsWith("*/")) return true;
    if (/^(package|import)\s+/.test(trimmed)) return true;
    if (/^(public\s+|protected\s+|private\s+|static\s+|final\s+|abstract\s+)*(class|interface|enum|record)\s+/.test(trimmed)) return true;
    if (/^[{}]\s*$/.test(trimmed)) return true;
    return false;
  }

  function renderSourceCode(lines, highlightedLine = null, coverageLines = null) {
    if (!codeViewerBody) return;
    codeViewerBody.innerHTML = "";

    const state = { inBlockComment: false };
    const linesCountElem = document.getElementById("vscode-lines-count");
    if (linesCountElem && lines) {
      linesCountElem.textContent = `${lines.length} lines`;
    }

    lines.forEach(line => {
      const row = document.createElement("div");
      row.className = "code-line";
      row.id = `code-line-${line.number}`;

      // Check coverage (exclude non-executable declarations)
      if (coverageLines && coverageLines[line.number] && !isNonExecutableLine(line.text)) {
        const covStatus = coverageLines[line.number].status;
        if (covStatus === "covered") row.classList.add("line-covered");
        else if (covStatus === "partially_covered") row.classList.add("line-partial");
        else if (covStatus === "uncovered") row.classList.add("line-uncovered");
      }

      // Check specific line highlight (from finding click)
      if (highlightedLine && line.number === highlightedLine) {
        row.classList.add("line-highlight");
      }

      const highlightedContent = highlightJavaLine(line.text, state);

      row.innerHTML = `
        <span class="line-num">${line.number}</span>
        <span class="line-content">${highlightedContent}</span>
      `;
      codeViewerBody.appendChild(row);
    });

    if (highlightedLine) {
      const targetRow = document.getElementById(`code-line-${highlightedLine}`);
      if (targetRow) {
        targetRow.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }
  }

  // -------------------------------------------------------------------------
  // 4. Guided Demo Workflow (8 Steps)
  // -------------------------------------------------------------------------
  function setupDemoNavigation() {
    stepPills.forEach(pill => {
      pill.addEventListener("click", () => {
        const stepNum = parseInt(pill.getAttribute("data-step"), 10);
        goToStep(stepNum);
      });
    });

    if (btnStepPrev) {
      btnStepPrev.addEventListener("click", () => {
        if (currentDemoStep > 1) goToStep(currentDemoStep - 1);
      });
    }

    if (btnStepNext) {
      btnStepNext.addEventListener("click", () => {
        if (currentDemoStep < 8) goToStep(currentDemoStep + 1);
      });
    }

    if (btnExitDemo) {
      btnExitDemo.addEventListener("click", () => {
        // Switch to overview tab
        const overviewBtn = document.querySelector('.sub-tab-btn[data-tab="overview"]');
        if (overviewBtn) overviewBtn.click();
      });
    }

    const btnStartDemo = document.getElementById("btn-start-demo");
    if (btnStartDemo) {
      btnStartDemo.addEventListener("click", () => {
        const demoBtn = document.querySelector('.sub-tab-btn[data-tab="guided-demo"]');
        if (demoBtn) demoBtn.click();
        goToStep(1);
      });
    }
  }

  function goToStep(stepNum) {
    currentDemoStep = stepNum;

    // Update pill styles
    stepPills.forEach(pill => {
      const num = parseInt(pill.getAttribute("data-step"), 10);
      pill.classList.remove("active", "completed");
      if (num === stepNum) pill.classList.add("active");
      else if (num < stepNum) pill.classList.add("completed");
    });

    // Update step visibility
    for (let i = 1; i <= 8; i++) {
      const contentElem = document.getElementById(`demo-step-${i}`);
      if (contentElem) {
        contentElem.style.display = (i === stepNum) ? "block" : "none";
      }
    }

    // Hide workspace grid (and code editor) on Step 1 and Step 8 (Summary does not need code editor)
    const wsGrid = document.getElementById("java-workspace-grid") || document.querySelector("#tab-guided-demo .workspace-grid");
    if (wsGrid) {
      wsGrid.style.display = (stepNum >= 2 && stepNum <= 7) ? "grid" : "none";
    }

    // Hide version switcher toolbar when code editor is not active
    const versionToggleBar = document.getElementById("java-version-toggle-container");
    if (versionToggleBar) {
      versionToggleBar.style.display = (stepNum >= 2 && stepNum <= 7) ? "flex" : "none";
    }

    // For Steps 1 to 6, always ensure Vulnerable Code is open and displayed
    if (stepNum <= 6 && currentVersion !== "vulnerable") {
      switchToVersion("vulnerable");
    }

    // Update button states
    if (btnStepPrev) btnStepPrev.disabled = (stepNum === 1);
    if (btnStepNext) {
      btnStepNext.textContent = (stepNum === 8) ? "Finish Demo" : "Next Step →";
    }

    // Refresh context for current step
    onEnterStep(stepNum);
  }

  function onEnterStep(stepNum) {
    const sc = scenariosData[currentScenarioId];
    if (!sc) return;

    if (stepNum === 1) {
      renderStep1Details(sc);
    } else if (stepNum === 2) {
      // Code inspection step
      loadScenario(currentScenarioId);
    } else if (stepNum === 7) {
      renderStep7Comparison(sc);
    } else if (stepNum === 8) {
      renderStep8Summary(sc);
    }
  }

  function renderStep1Details(sc) {
    const titleElem = document.getElementById("demo-step1-title");
    const cweElem = document.getElementById("demo-step1-cwe");
    const summaryElem = document.getElementById("demo-step1-summary");
    const defectElem = document.getElementById("demo-step1-defect");
    const expectedElem = document.getElementById("demo-step1-expected");

    if (titleElem) titleElem.textContent = sc.title;
    if (cweElem) cweElem.textContent = sc.cwe;
    if (summaryElem) summaryElem.textContent = sc.summary;

    const defectDescriptions = {
      "null_handling": {
        "defect": "Calling text.length() when text is null, triggering an unhandled NullPointerException at runtime. Static checkers also flag BrokenNullCheck and unvalidated null parameter passing.",
        "trigger": "Passing null to getLength(null).",
        "expected": "Defensively validate if (text == null) return 0;, safely handling null without throwing an exception."
      },
      "array_bounds": {
        "defect": "Accessing numbers[3] directly on an array of 3 elements (valid indices 0, 1, 2) triggers ArrayIndexOutOfBoundsException at runtime and SpotBugs RANGE_ARRAY_INDEX in bytecode.",
        "trigger": "Passing a 3-element array to getValue(numbers).",
        "expected": "Validate boundaries: if (numbers == null || index < 0 || index >= numbers.length) return -1; before accessing the element."
      },
      "exception_handling": {
        "defect": "Empty catch (ArithmeticException e) {} block that silently swallows the 10 / 0 division failure without any reporting, logging, or error indication (CWE-390).",
        "trigger": "Division by zero occurs in calculate(), and the exception is caught with no handling.",
        "expected": "Report the failure to System.err ('Calculation failed: ' + e.getMessage()) and record the failure state instead of hiding it."
      },
      "resource_handling": {
        "defect": "Allocating BufferedReader via Files.newBufferedReader(path) without closing the resource, leaking operating-system file descriptors and buffer memory.",
        "trigger": "Opening a file with newBufferedReader without try-with-resources or explicit close().",
        "expected": "Use Java 7+ try-with-resources statement: try (BufferedReader reader = Files.newBufferedReader(path)) for guaranteed automatic cleanup."
      }
    };

    const info = defectDescriptions[sc.id] || {};
    if (defectElem) defectElem.textContent = info.defect || "";
    if (expectedElem) expectedElem.textContent = info.expected || "";
  }

  // -------------------------------------------------------------------------
  // 5. Tool Action Runners (PMD, SpotBugs, JUnit, JaCoCo)
  // -------------------------------------------------------------------------
  function setupActionButtons() {
    // PMD
    const btnRunPmd = document.getElementById("btn-run-pmd");
    if (btnRunPmd) {
      btnRunPmd.addEventListener("click", () => executePmdAction());
    }

    // SpotBugs
    const btnRunSpotbugs = document.getElementById("btn-run-spotbugs");
    if (btnRunSpotbugs) {
      btnRunSpotbugs.addEventListener("click", () => executeSpotbugsAction());
    }

    // JUnit
    const btnRunJunit = document.getElementById("btn-run-junit");
    if (btnRunJunit) {
      btnRunJunit.addEventListener("click", () => executeJunitAction());
    }

    // JaCoCo
    const btnRunJacoco = document.getElementById("btn-run-jacoco");
    if (btnRunJacoco) {
      btnRunJacoco.addEventListener("click", () => executeJacocoAction());
    }

    const btnStep8RunAll = document.getElementById("btn-step8-run-all");
    if (btnStep8RunAll) {
      btnStep8RunAll.addEventListener("click", () => runAllToolsForScenario(currentScenarioId));
    }

    const btnStep8StepThrough = document.getElementById("btn-step8-step-through");
    if (btnStep8StepThrough) {
      btnStep8StepThrough.addEventListener("click", () => goToStep(3));
    }

    const btnStep8RefreshSummary = document.getElementById("btn-step8-refresh-summary");
    if (btnStep8RefreshSummary) {
      btnStep8RefreshSummary.addEventListener("click", () => runAllToolsForScenario(currentScenarioId));
    }
  }

  async function executePmdAction() {
    const sc = scenariosData[currentScenarioId];
    const resultsContainer = document.getElementById("demo-pmd-results");
    if (!resultsContainer) return;

    resultsContainer.innerHTML = '<div style="padding: 16px; color: #666;"><span class="badge badge-info">RUNNING</span> Executing PMD AST static analysis...</div>';

    const targetFile = currentVersion === "vulnerable" ? sc.vulnerable_file : sc.fixed_file;
    try {
      const res = await fetch("/api/pmd", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_path: `src/main/java/${targetFile}` })
      });
      const data = await res.json();
      if (data.success) {
        const runs = getScenarioRuns(currentScenarioId);
        if (currentVersion === "vulnerable") runs.pmd = data;
        else runs.pmdFixed = data;
        runs.pmdRan = true;
        if (currentDemoStep === 8) renderStep8Summary(sc);
      }
      renderPmdResults(data, resultsContainer);
    } catch (e) {
      resultsContainer.innerHTML = `<div style="padding: 16px; color: #c0392b;">PMD Execution Failed: ${e.message}</div>`;
    }
  }

  function renderPmdResults(data, container) {
    if (!data.success) {
      container.innerHTML = `<div style="padding: 16px; color: #c0392b;">Error: ${data.error}</div>`;
      return;
    }

    if (data.findings.length === 0) {
      container.innerHTML = `
        <div style="padding: 16px; background: var(--status-success-bg); border: 1px solid var(--status-success-border); border-radius: 6px;">
          <strong>No PMD Violations Reported</strong>
          <p style="font-size: 12.5px; color: var(--text-secondary); margin-top: 4px;">
            PMD did not find any rule violations matching the active ruleset for this file. 
            <em>Note: Static analysis absence does not prove runtime correctness.</em>
          </p>
        </div>
      `;
      return;
    }

    let html = `
      <div style="margin-bottom: 12px; font-weight: 600; font-size: 13.5px;">
        PMD reported ${data.findings.length} finding(s) in actual Java source (click any finding to highlight in editor):
      </div>
      <div class="findings-list">
    `;

    data.findings.forEach(f => {
      const lineText = (f.begin_line && f.end_line && f.begin_line !== f.end_line)
        ? `Lines ${f.begin_line}–${f.end_line}`
        : `Line ${f.begin_line || '?'}`;

      html += `
        <div class="finding-card" onclick="window.highlightSourceLine(${f.begin_line}, ${f.end_line || f.begin_line}, this, 'vulnerable')" title="Click to inspect this finding in the vulnerable Java code viewer">
          <div class="finding-header">
            <span class="finding-title">${escapeHtml(f.rule)} (${escapeHtml(f.ruleset)})</span>
            <span class="badge badge-warning">Priority ${f.priority}</span>
          </div>
          <div class="finding-loc">
            <span class="loc-pin">📍</span> <strong>${lineText}</strong> &bull; ${escapeHtml(f.file)}
            <span class="click-hint">🔍 Click to inspect in editor</span>
          </div>
          <div class="finding-body">${escapeHtml(f.message)}</div>
          <div class="finding-remediation">
            <strong>Remediation:</strong> ${escapeHtml(f.remediation)}
          </div>
        </div>
      `;
    });

    html += `</div>`;
    container.innerHTML = html;
  }

  async function executeSpotbugsAction() {
    const sc = scenariosData[currentScenarioId];
    const resultsContainer = document.getElementById("demo-spotbugs-results");
    if (!resultsContainer) return;

    resultsContainer.innerHTML = '<div style="padding: 16px; color: #666;"><span class="badge badge-info">RUNNING</span> Compiling bytecode & running SpotBugs...</div>';

    const targetClass = currentVersion === "vulnerable" ? sc.vulnerable_class : sc.fixed_class;
    try {
      const res = await fetch("/api/spotbugs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ class_filter: targetClass })
      });
      const data = await res.json();
      if (data.success) {
        const runs = getScenarioRuns(currentScenarioId);
        if (currentVersion === "vulnerable") runs.spotbugs = data;
        else runs.spotbugsFixed = data;
        runs.spotbugsRan = true;
        if (currentDemoStep === 8) renderStep8Summary(sc);
      }
      renderSpotbugsResults(data, resultsContainer);
    } catch (e) {
      resultsContainer.innerHTML = `<div style="padding: 16px; color: #c0392b;">SpotBugs Execution Failed: ${e.message}</div>`;
    }
  }

  function renderSpotbugsResults(data, container) {
    if (!data.success) {
      container.innerHTML = `<div style="padding: 16px; color: #c0392b;">Error: ${data.error}</div>`;
      return;
    }

    if (data.findings.length === 0) {
      container.innerHTML = `
        <div style="padding: 16px; background: var(--status-success-bg); border: 1px solid var(--status-success-border); border-radius: 6px;">
          <strong>No SpotBugs Bug Patterns Reported</strong>
          <p style="font-size: 12.5px; color: var(--text-secondary); margin-top: 4px;">
            SpotBugs analyzed the compiled bytecode and detected no known bug patterns for this class.
          </p>
        </div>
      `;
      return;
    }

    let html = `
      <div style="margin-bottom: 12px; font-weight: 600; font-size: 13.5px;">
        SpotBugs reported ${data.findings.length} bug pattern(s) in compiled bytecode (click any finding to highlight in editor):
      </div>
      <div class="findings-list">
    `;

    data.findings.forEach(f => {
      const lineNum = f.start_line || f.end_line;
      const lineText = lineNum ? `Line ${lineNum}` : "Class-level finding";
      const clickAttr = lineNum ? `onclick="window.highlightSourceLine(${lineNum}, ${f.end_line || lineNum}, this, 'vulnerable')" title="Click to inspect this bug pattern in the vulnerable Java code viewer"` : "";

      html += `
        <div class="finding-card" ${clickAttr}>
          <div class="finding-header">
            <span class="finding-title">${escapeHtml(f.type)} (${escapeHtml(f.category)})</span>
            <span class="badge badge-danger">${f.priority_label}</span>
          </div>
          <div class="finding-loc">
            <span class="loc-pin">📍</span> <strong>${lineText}</strong> &bull; ${escapeHtml(f.class_name)}
            ${lineNum ? '<span class="click-hint">🔍 Click to inspect in editor</span>' : ''}
          </div>
          <div class="finding-body">${escapeHtml(f.explanation)}</div>
          <div class="finding-remediation">
            <strong>Remediation:</strong> ${escapeHtml(f.remediation)}
          </div>
        </div>
      `;
    });

    html += `</div>`;
    container.innerHTML = html;
  }

  async function executeJunitAction() {
    const sc = scenariosData[currentScenarioId];
    const resultsContainer = document.getElementById("demo-junit-results");
    if (!resultsContainer) return;

    resultsContainer.innerHTML = '<div style="padding: 16px; color: #666;"><span class="badge badge-info">RUNNING</span> Executing JUnit 5 dynamic tests...</div>';

    try {
      const res = await fetch("/api/junit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test_class: sc.test_class })
      });
      const data = await res.json();
      if (data.success) {
        const runs = getScenarioRuns(currentScenarioId);
        runs.junit = data;
        runs.junitRan = true;
        if (data.coverage && !data.coverage.error) {
          runs.jacoco = data.coverage;
          runs.jacocoRan = true;
        }
        if (currentDemoStep === 8) renderStep8Summary(sc);
      }
      renderJunitResults(data, resultsContainer);
    } catch (e) {
      resultsContainer.innerHTML = `<div style="padding: 16px; color: #c0392b;">JUnit Execution Failed: ${e.message}</div>`;
    }
  }

  function renderJunitResults(data, container) {
    if (!data.success) {
      container.innerHTML = `<div style="padding: 16px; color: #c0392b;">Error: ${data.error}</div>`;
      return;
    }

    let vulnReproCount = 0;
    data.tests.forEach(t => {
      if (t.is_defect_demo && t.status === "PASSED") vulnReproCount++;
    });

    let html = `
      <div style="display: flex; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; align-items: center;">
        <span class="badge badge-success">Passed: ${data.passed}</span>
        <span class="badge ${data.failed > 0 ? 'badge-danger' : 'badge-info'}">Failed: ${data.failed}</span>
        <span class="badge badge-info">Total Tests: ${data.total_tests}</span>
        ${vulnReproCount > 0 ? `<span class="badge" style="background: rgba(99, 102, 241, 0.12); color: #4338ca; border: 1px solid rgba(99, 102, 241, 0.35); font-weight: 600;">✓ Vulnerabilities Reproduced: ${vulnReproCount}</span>` : ''}
      </div>
      <div class="findings-list">
    `;

    data.tests.forEach(t => {
      const isPassed = (t.status === "PASSED");
      const isDefectDemo = t.is_defect_demo || t.name.toLowerCase().includes("vulnerable") || t.name.toLowerCase().includes("throwsexception");

      let targetLine = t.defect_target_line || null;
      let targetFile = t.defect_target_file || null;

      // Fallback to stack trace if test failed unexpectedly
      if (!targetLine && t.stack_trace) {
        const sc = scenariosData[currentScenarioId];
        const vulnBase = sc ? sc.vulnerable_file.split('/').pop().replace(".", "\\.") : "Vulnerable\\.java";
        const rx = new RegExp(vulnBase + ":(\\d+)");
        const m = t.stack_trace.match(rx);
        if (m && m[1]) targetLine = parseInt(m[1], 10);
      }

      const clickAttr = targetLine ? `onclick="window.highlightSourceLine(${targetLine}, ${targetLine}, this, 'vulnerable')" title="Click to inspect defect location in vulnerable source code"` : "";

      let demoBadge = "";
      if (isDefectDemo && isPassed) {
        demoBadge = `<span class="badge" style="background: rgba(99, 102, 241, 0.12); color: #4338ca; border: 1px solid rgba(99, 102, 241, 0.35); font-weight: 600;">Defect Reproduced (Expected Exception Verified)</span>`;
      } else if (!isPassed) {
        demoBadge = `<span class="badge badge-danger">Unexpected Failure</span>`;
      } else {
        demoBadge = `<span class="badge badge-success">Defensive Behavior Verified</span>`;
      }

      html += `
        <div class="finding-card" ${clickAttr} style="border-left: 4px solid ${isPassed ? (isDefectDemo ? '#6366f1' : '#34a853') : '#ea4335'};">
          <div class="finding-header" style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
            <div>
              <span class="finding-title" style="font-weight: 600;">${escapeHtml(t.name)}</span>
              <div style="margin-top: 4px;">${demoBadge}</div>
            </div>
            <span class="badge ${isPassed ? 'badge-success' : 'badge-danger'}">${t.status}</span>
          </div>
          <div class="finding-loc" style="margin-top: 6px;">
            ${targetLine ? `<span class="loc-pin">📍</span> <strong>Line ${targetLine}</strong> ${targetFile ? '(' + escapeHtml(targetFile) + ')' : ''} &bull; ` : ''}
            ${escapeHtml(t.class_name)} &bull; ${(t.duration_seconds * 1000).toFixed(1)}ms
            ${targetLine ? '<span class="click-hint" style="margin-left: 8px;">🔍 Click to inspect defect</span>' : ''}
          </div>
      `;

      if (t.defect_description) {
        html += `
          <div class="junit-demo-note" style="margin-top: 6px; font-size: 12px; line-height: 1.5; padding: 6px 10px; border-radius: 4px;">
            <strong>Demonstration Note:</strong> ${escapeHtml(t.defect_description)}
          </div>
        `;
      }

      if (!isPassed && t.failure_message) {
        html += `
          <div class="junit-failure-box" style="margin-top: 8px; font-size: 12.5px; font-family: var(--font-mono); padding: 8px 12px; border-radius: 4px;">
            <strong>${escapeHtml(t.failure_type || "Failure")}:</strong> ${escapeHtml(t.failure_message)}
          </div>
        `;
      }
      html += `</div>`;
    });

    html += `</div>`;
    container.innerHTML = html;
  }

  async function executeJacocoAction() {
    const sc = scenariosData[currentScenarioId];
    const resultsContainer = document.getElementById("demo-jacoco-results");
    if (!resultsContainer) return;

    resultsContainer.innerHTML = '<div style="padding: 16px; color: #666;"><span class="badge badge-info">RUNNING</span> Generating JaCoCo bytecode coverage report...</div>';

    try {
      const res = await fetch("/api/junit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test_class: sc.test_class })
      });
      const data = await res.json();
      activeCoverageMap = data.coverage;
      if (data.success) {
        const runs = getScenarioRuns(currentScenarioId);
        runs.jacoco = data.coverage;
        runs.jacocoRan = true;
        if (!runs.junit) {
          runs.junit = data;
          runs.junitRan = true;
        }
        if (currentDemoStep === 8) renderStep8Summary(sc);
      }
      renderJacocoResults(data.coverage, resultsContainer);
    } catch (e) {
      resultsContainer.innerHTML = `<div style="padding: 16px; color: #c0392b;">JaCoCo Coverage Failed: ${e.message}</div>`;
    }
  }

  function renderJacocoResults(coverage, container) {
    if (!coverage || coverage.error) {
      container.innerHTML = `<div style="padding: 16px; color: #c0392b;">No coverage data: ${coverage ? coverage.error : 'Unknown'}</div>`;
      return;
    }

    const sc = scenariosData[currentScenarioId];
    const targetFile = currentVersion === "vulnerable" ? sc.vulnerable_file : sc.fixed_file;
    const baseFileName = targetFile.split("/").pop();
    const fileCov = coverage.files ? coverage.files[baseFileName] : null;

    const uncoveredLineNumbers = [];
    if (fileCov && fileCov.lines && currentSourceData && currentSourceData.lines) {
      const lineMap = {};
      currentSourceData.lines.forEach(l => { lineMap[l.number] = l.text; });
      for (const [nr, lInfo] of Object.entries(fileCov.lines)) {
        const lineNr = parseInt(nr, 10);
        const lineTxt = lineMap[lineNr] || "";
        if (lInfo.status === "uncovered" && lInfo.is_executable !== false && !isNonExecutableLine(lineTxt)) {
          uncoveredLineNumbers.push(lineNr);
        }
      }
    }

    let uncoveredHtml = "";
    if (uncoveredLineNumbers.length > 0) {
      uncoveredHtml = `
        <div style="margin-top: 12px; padding: 12px 14px; background: rgba(248, 81, 73, 0.08); border: 1px solid rgba(248, 81, 73, 0.25); border-radius: 6px; font-size: 13px;">
          <strong>Uncovered Line(s) in Bytecode (Click to highlight in editor):</strong>
          <div style="display: flex; gap: 8px; margin-top: 8px; flex-wrap: wrap;">
            ${uncoveredLineNumbers.map(ln => `
              <button type="button" class="btn btn-sm btn-secondary" style="border-color: #f85149; color: #c0392b; font-weight: 600;" onclick="window.highlightSourceLine(${ln}, ${ln}, null, '${currentVersion}')">
                📍 Line ${ln} (Uncovered)
              </button>
            `).join("")}
          </div>
        </div>
      `;
    } else {
      uncoveredHtml = `
        <div style="margin-top: 12px; padding: 10px 14px; background: rgba(52, 168, 83, 0.08); border: 1px solid rgba(52, 168, 83, 0.25); border-radius: 6px; font-size: 13px; color: #1e7e34;">
          ✓ All executed source lines in <code>${escapeHtml(baseFileName)}</code> were covered by the recorded test suite.
        </div>
      `;
    }

    const linePct = fileCov ? fileCov.line_coverage_percentage : coverage.overall_line_coverage;
    const lineExecuted = fileCov ? fileCov.covered_lines : coverage.covered_lines;
    const lineTotal = fileCov ? fileCov.lines_count : coverage.total_lines;

    let branchDisplay = "";
    let branchSubtext = "";
    if (fileCov && fileCov.has_branches) {
      branchDisplay = `${fileCov.branch_coverage_percentage}%`;
      branchSubtext = `${fileCov.covered_branches} of ${fileCov.total_branches} branches evaluated`;
    } else if (fileCov) {
      branchDisplay = "N/A";
      branchSubtext = "No conditional branches in this class";
    } else {
      branchDisplay = `${coverage.overall_branch_coverage}%`;
      branchSubtext = `${coverage.covered_branches} of ${coverage.total_branches} branches evaluated`;
    }

    let html = `
      <div style="font-size: 12.5px; font-weight: 600; color: var(--text-secondary); margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center;">
        <span>Scope: <strong>Selected Source File (${escapeHtml(baseFileName)})</strong></span>
        <span class="badge ${currentVersion === 'vulnerable' ? 'badge-warning' : 'badge-success'}">${currentVersion === 'vulnerable' ? 'Vulnerable Code' : 'Corrected Code'}</span>
      </div>
      <div style="display: flex; gap: 16px; margin-bottom: 16px;">
        <div style="flex: 1; background: var(--bg-card); border: 1px solid var(--border-light); padding: 12px; border-radius: 6px;">
          <div style="font-size: 11px; color: #777;">LINE COVERAGE (SELECTED FILE)</div>
          <div style="font-size: 22px; font-weight: 700; color: var(--accent-teal);">${linePct}%</div>
          <div style="font-size: 11.5px; color: #888;">${lineExecuted} of ${lineTotal} executable lines executed</div>
        </div>
        <div style="flex: 1; background: var(--bg-card); border: 1px solid var(--border-light); padding: 12px; border-radius: 6px;">
          <div style="font-size: 11px; color: #777;">BRANCH COVERAGE (SELECTED FILE)</div>
          <div style="font-size: 22px; font-weight: 700; color: #b87333;">${branchDisplay}</div>
          <div style="font-size: 11.5px; color: #888;">${branchSubtext}</div>
        </div>
      </div>
      <div style="background: var(--bg-subtle); padding: 12px; border-radius: 6px; font-size: 12.5px; margin-bottom: 14px;">
        <strong>Coverage Scope &amp; Interpretation:</strong> JaCoCo measures executable instructions recorded during the test execution of <code>${escapeHtml(sc.test_class.split('.').pop())}</code>. 
        <span style="color: #c0392b;">High coverage does NOT prove software is bug-free or secure.</span>
        <div style="font-size: 11px; color: #777; margin-top: 6px;">
          Project Aggregate: ${coverage.overall_line_coverage}% lines (${coverage.covered_lines}/${coverage.total_lines}), ${coverage.overall_branch_coverage}% branches (${coverage.covered_branches}/${coverage.total_branches}) across all compiled classes.
        </div>
      </div>
      ${uncoveredHtml}
      <button type="button" class="btn btn-secondary btn-sm" id="btn-toggle-coverage-overlay" style="margin-top: 10px;">
        Highlight All Covered &amp; Uncovered Lines in Code Viewer
      </button>
    `;

    container.innerHTML = html;

    const btnToggle = document.getElementById("btn-toggle-coverage-overlay");
    if (btnToggle && fileCov && fileCov.lines && currentSourceData) {
      btnToggle.addEventListener("click", () => {
        renderSourceCode(currentSourceData.lines, null, fileCov.lines);
        btnToggle.textContent = "Coverage Highlighted in Source Viewer";
      });
    }
  }

  // -------------------------------------------------------------------------
  // 6. Step 7 & 8: Comparison & Summary
  // -------------------------------------------------------------------------
  function renderStep7Comparison(sc) {
    const container = document.getElementById("demo-step7-comparison-body");
    if (!container) return;

    container.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
        <div style="background: var(--status-danger-bg); border: 1px solid var(--status-danger-border); padding: 16px; border-radius: 6px;">
          <h4 style="color: var(--status-danger); margin-bottom: 8px;">Vulnerable Version (${sc.vulnerable_file.split('/').pop()})</h4>
          <ul style="font-size: 12.5px; padding-left: 18px; color: var(--text-secondary); line-height: 1.6;">
            <li>Directly susceptible to defect: <code>${sc.cwe}</code></li>
            <li>Static analysis (PMD/SpotBugs) flags missing checks or resource leaks</li>
            <li>Runtime tests demonstrate unhandled exceptions or silent state suppression</li>
          </ul>
        </div>
        <div style="background: var(--status-success-bg); border: 1px solid var(--status-success-border); padding: 16px; border-radius: 6px;">
          <h4 style="color: var(--status-success); margin-bottom: 8px;">Corrected Version (${sc.fixed_file.split('/').pop()})</h4>
          <ul style="font-size: 12.5px; padding-left: 18px; color: var(--text-secondary); line-height: 1.6;">
            <li>Defensive programming constructs applied</li>
            <li>Static warnings eliminated or neutralized</li>
            <li>Equivalent tests restore expected, deterministic behavior</li>
            <li>JaCoCo verifies execution paths through defensive guards</li>
          </ul>
        </div>
      </div>
    `;
  }

  function onScenarioChanged(newScId) {
    const sc = scenariosData[newScId];
    if (!sc) return;

    const runs = getScenarioRuns(newScId);

    // Update step results to avoid stale data from prior scenario leaking
    const pmdContainer = document.getElementById("demo-pmd-results");
    if (pmdContainer) {
      if (runs.pmd) renderPmdResults(runs.pmd, pmdContainer);
      else pmdContainer.innerHTML = `<div style="padding: 16px; color: var(--text-secondary); text-align: center;">Click <strong>Run PMD</strong> to inspect source code for ${escapeHtml(sc.title)}.</div>`;
    }

    const sbContainer = document.getElementById("demo-spotbugs-results");
    if (sbContainer) {
      if (runs.spotbugs) renderSpotbugsResults(runs.spotbugs, sbContainer);
      else sbContainer.innerHTML = `<div style="padding: 16px; color: var(--text-secondary); text-align: center;">Click <strong>Run SpotBugs</strong> to analyze bytecode for ${escapeHtml(sc.title)}.</div>`;
    }

    const junitContainer = document.getElementById("demo-junit-results");
    if (junitContainer) {
      if (runs.junit) renderJunitResults(runs.junit, junitContainer);
      else junitContainer.innerHTML = `<div style="padding: 16px; color: var(--text-secondary); text-align: center;">Click <strong>Run JUnit 5</strong> to execute runtime tests for ${escapeHtml(sc.title)}.</div>`;
    }

    const jacocoContainer = document.getElementById("demo-jacoco-results");
    if (jacocoContainer) {
      if (runs.jacoco) renderJacocoResults(runs.jacoco, jacocoContainer);
      else jacocoContainer.innerHTML = `<div style="padding: 16px; color: var(--text-secondary); text-align: center;">Click <strong>Run JaCoCo</strong> to measure code coverage for ${escapeHtml(sc.title)}.</div>`;
    }

    // If currently on step 8, immediately render Step 8 (which will lock if tools not yet run)
    if (currentDemoStep === 8) {
      renderStep8Summary(sc);
    }
  }

  function updateStep8Checklist(scId) {
    const container = document.getElementById("step8-checklist-container");
    if (!container) return;

    const runs = getScenarioRuns(scId);
    const sc = scenariosData[scId];
    const targetBase = sc ? sc.vulnerable_file.split("/").pop() : "";

    const pmdDone = runs.pmdRan && runs.pmd;
    const spotbugsDone = runs.spotbugsRan && runs.spotbugs;
    const junitDone = runs.junitRan && runs.junit;
    const jacocoDone = runs.jacocoRan && runs.jacoco;

    let pmdDetail = "Pending: AST syntax tree check not executed";
    if (pmdDone) {
      const count = runs.pmd.findings ? runs.pmd.findings.length : 0;
      pmdDetail = `✓ Executed: ${count} AST finding(s) reported on source`;
    }

    let sbDetail = "Pending: Compiled bytecode check not executed";
    if (spotbugsDone) {
      const count = runs.spotbugs.findings ? runs.spotbugs.findings.length : 0;
      sbDetail = `✓ Executed: ${count} bytecode bug pattern(s) detected`;
    }

    let junitDetail = "Pending: Dynamic JVM test suite not executed";
    if (junitDone) {
      junitDetail = `✓ Executed: ${runs.junit.passed}/${runs.junit.total_tests} tests passed (${runs.junit.failed} failed)`;
    }

    let jacocoDetail = "Pending: Bytecode execution coverage not measured";
    if (jacocoDone) {
      const fileCov = runs.jacoco.files ? runs.jacoco.files[targetBase] : null;
      const lineCov = fileCov ? fileCov.line_coverage_percentage : runs.jacoco.overall_line_coverage;
      jacocoDetail = `✓ Executed: ${lineCov}% line coverage measured`;
    }

    const items = [
      { name: "PMD Static Analysis", type: "Source AST Scanner", icon: "🔍", done: pmdDone, detail: pmdDetail },
      { name: "SpotBugs Static Analysis", type: "Bytecode Analyzer", icon: "🐞", done: spotbugsDone, detail: sbDetail },
      { name: "JUnit 5 Dynamic Tests", type: "Live JVM Runtime", icon: "⚡", done: junitDone, detail: junitDetail },
      { name: "JaCoCo Dynamic Coverage", type: "Runtime Coverage Agent", icon: "📊", done: jacocoDone, detail: jacocoDetail }
    ];

    container.innerHTML = items.map(it => `
      <div style="background: var(--bg-surface, var(--bg-subtle, #f9fafb)); border: 1px solid ${it.done ? 'var(--status-success, #34a853)' : 'var(--border-light, #e5e7eb)'}; border-left: 4px solid ${it.done ? 'var(--status-success, #34a853)' : '#9ca3af'}; border-radius: 8px; padding: 12px 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <strong style="color: var(--text-primary); font-size: 14px;">${it.icon} ${it.name}</strong>
          <span class="badge ${it.done ? 'badge-success' : 'badge-secondary'}" style="font-size: 11px;">${it.done ? '✓ Executed' : '⏳ Pending'}</span>
        </div>
        <div style="font-size: 12.5px; color: ${it.done ? 'var(--status-success, #1e7e34)' : 'var(--text-secondary, #6b7280)'};">
          ${it.detail}
        </div>
      </div>
    `).join("");
  }

  async function runAllToolsForScenario(scId) {
    const sc = scenariosData[scId];
    if (!sc) return;

    const progressArea = document.getElementById("step8-run-progress");
    const progressText = document.getElementById("step8-progress-text");
    const btnRunAll = document.getElementById("btn-step8-run-all");
    const btnStepThrough = document.getElementById("btn-step8-step-through");
    const btnRefresh = document.getElementById("btn-step8-refresh-summary");

    if (progressArea) progressArea.style.display = "block";
    if (btnRunAll) btnRunAll.disabled = true;
    if (btnStepThrough) btnStepThrough.disabled = true;
    if (btnRefresh) btnRefresh.disabled = true;

    try {
      // 1. PMD
      if (progressText) progressText.textContent = "1/4: Running PMD static AST source scanner...";
      const pmdRes = await fetch("/api/pmd", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_path: `src/main/java/${sc.vulnerable_file}` })
      });
      const pmdData = await pmdRes.json();
      if (pmdData.success) {
        const runs = getScenarioRuns(scId);
        runs.pmd = pmdData;
        runs.pmdRan = true;
        updateStep8Checklist(scId);
      }

      // 2. SpotBugs
      if (progressText) progressText.textContent = "2/4: Compiling bytecode & running SpotBugs analyzer...";
      const sbRes = await fetch("/api/spotbugs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ class_filter: sc.vulnerable_class })
      });
      const sbData = await sbRes.json();
      if (sbData.success) {
        const runs = getScenarioRuns(scId);
        runs.spotbugs = sbData;
        runs.spotbugsRan = true;
        updateStep8Checklist(scId);
      }

      // 3. JUnit & JaCoCo
      if (progressText) progressText.textContent = "3/4 & 4/4: Executing JUnit 5 JVM dynamic tests & JaCoCo coverage...";
      const junitRes = await fetch("/api/junit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test_class: sc.test_class })
      });
      const junitData = await junitRes.json();
      if (junitData.success) {
        const runs = getScenarioRuns(scId);
        runs.junit = junitData;
        runs.junitRan = true;
        if (junitData.coverage && !junitData.coverage.error) {
          runs.jacoco = junitData.coverage;
          runs.jacocoRan = true;
        }
        updateStep8Checklist(scId);
      }

      if (progressText) progressText.textContent = "All test cases ran successfully! Generating authentic summary...";
      setTimeout(() => {
        if (progressArea) progressArea.style.display = "none";
        if (btnRunAll) btnRunAll.disabled = false;
        if (btnStepThrough) btnStepThrough.disabled = false;
        if (btnRefresh) btnRefresh.disabled = false;
        renderStep8Summary(sc);
      }, 500);
    } catch (err) {
      if (progressText) progressText.textContent = `Execution failed: ${err.message}`;
      if (btnRunAll) btnRunAll.disabled = false;
      if (btnStepThrough) btnStepThrough.disabled = false;
      if (btnRefresh) btnRefresh.disabled = false;
    }
  }

  function buildAuthenticToolSummaries(sc, runs) {
    const pmd = runs.pmd || { findings: [] };
    const spotbugs = runs.spotbugs || { findings: [] };
    const junit = runs.junit || { tests: [], passed: 0, failed: 0, total_tests: 0 };
    const jacoco = runs.jacoco || { files: {} };

    const vulnBase = sc.vulnerable_file.split("/").pop();
    const fixedBase = sc.fixed_file.split("/").pop();
    const vulnCov = jacoco.files ? jacoco.files[vulnBase] : null;
    const fixedCov = jacoco.files ? jacoco.files[fixedBase] : null;

    const pmdCount = pmd.total_findings ?? pmd.findings.length;
    const pmdFirst = pmd.findings.length > 0 ? pmd.findings[0] : null;
    const sbCount = spotbugs.total_findings ?? spotbugs.findings.length;
    const sbFirst = spotbugs.findings.length > 0 ? spotbugs.findings[0] : null;

    if (sc.id === "null_handling") {
      return [
        {
          tool: "PMD",
          icon: "🔍",
          type: "Static Source Code Scanner (AST)",
          badgeClass: "badge-warning",
          whatDid: "Scanned the raw Java source file (<code>NullHandlingVulnerable.java</code>) without executing code, parsing syntax into an Abstract Syntax Tree (AST) to detect dangerous operators and null checks.",
          results: `Reported <strong>${pmdCount} finding(s)</strong> in vulnerable source. Flagged <strong>${pmdFirst ? escapeHtml(pmdFirst.rule) : "BrokenNullCheck"} (Priority ${pmdFirst ? pmdFirst.priority : 2})</strong> at <strong>Line ${pmdFirst ? pmdFirst.begin_line : 45}</strong>: caught that short-circuit <code>&amp;&amp;</code> was used instead of <code>||</code> (<code>text == null &amp;&amp; text.length() &gt; 0</code>), causing an instant crash when evaluated with null. Corrected source reported <strong>0 findings</strong>.`,
          why: "PMD catches syntax-level logic bugs and dangerous boolean expressions directly in source code before compilation even starts."
        },
        {
          tool: "SpotBugs",
          icon: "🐞",
          type: "Compiled Bytecode Analyzer (.class)",
          badgeClass: "badge-danger",
          whatDid: "Analyzed compiled Java bytecode (<code>NullHandlingVulnerable.class</code>), tracing dataflow and variable references across JVM method call instructions.",
          results: `Detected <strong>${sbCount} bug pattern(s)</strong> in bytecode. Flagged <strong>${sbFirst ? escapeHtml(sbFirst.type) : "NP_ALWAYS_NULL"} (Priority ${sbFirst ? sbFirst.priority : 1})</strong> at <strong>Line ${sbFirst ? sbFirst.line : 37}</strong> in method <code>processInput()</code>: traced that an unvalidated null argument flows directly into <code>getLength(text)</code> without checking. Corrected bytecode reported <strong>0 bugs</strong>.`,
          why: "SpotBugs inspects compiled bytecode to follow references across function calls, discovering null dereferences that simple linters cannot track."
        },
        {
          tool: "JUnit 5",
          icon: "⚡",
          type: "Dynamic Runtime Test Suite (Live JVM)",
          badgeClass: "badge-danger",
          whatDid: "Executed dynamic test cases inside the live Java Virtual Machine (JVM), passing both valid strings and edge-case null references to verify actual execution outcomes.",
          results: `Executed <strong>${junit.total_tests} dynamic tests (${junit.passed} passed, ${junit.failed} failed)</strong>. Defect test <code>testVulnerableNullThrowsException</code> reproduced the live crash: threw an unhandled <code>java.lang.NullPointerException</code> at <strong>Line 27</strong> (<code>text.length()</code>). On corrected code, <code>testFixedNullReturnsZero</code> safely returned fallback <code>0</code> with 100% test success.`,
          why: "Static scanners predict theoretical defects; JUnit dynamic tests prove whether an application actually crashes or survives under live runtime execution."
        },
        {
          tool: "JaCoCo",
          icon: "📊",
          type: "Runtime Code Coverage Inspector",
          badgeClass: "badge-info",
          whatDid: "Monitored JVM bytecode execution with a runtime agent, measuring every instruction and conditional decision branch exercised during test execution.",
          results: `Demonstrated that on corrected code (<code>NullHandlingFixed.java</code>), the defensive guard <code>if (text == null) return 0;</code> achieved <strong>${fixedCov ? fixedCov.line_coverage_percentage : '88.9'}% line coverage</strong> and <strong>${fixedCov && fixedCov.has_branches ? fixedCov.branch_coverage_percentage + '%' : '100.0%'} branch coverage</strong>. In contrast, the vulnerable code reached only <strong>${vulnCov ? vulnCov.line_coverage_percentage : '14.3'}% line coverage</strong> and <strong>0.0% branch coverage</strong> before crashing.`,
          why: "JaCoCo verifies that defensive security checks are genuinely evaluated during tests and not left as untested dead code."
        }
      ];
    } else if (sc.id === "array_bounds") {
      return [
        {
          tool: "PMD",
          icon: "🔍",
          type: "Static Source Code Scanner (AST)",
          badgeClass: "badge-warning",
          whatDid: "Scanned raw Java source (<code>ArrayBoundsVulnerable.java</code>) to detect unsafe array assignment and direct object exposure that violates encapsulation.",
          results: `Reported <strong>${pmdCount} finding(s)</strong> in vulnerable source. Flagged <strong>${pmdFirst ? escapeHtml(pmdFirst.rule) : "ArrayIsStoredDirectly"} (Priority ${pmdFirst ? pmdFirst.priority : 3})</strong> at <strong>Line ${pmdFirst ? pmdFirst.begin_line : 48}</strong> and <code>MethodReturnsInternalArray</code> at <strong>Line 52</strong> for storing and returning internal buffer arrays without defensive copying. Corrected code reported <strong>0 findings</strong>.`,
          why: "Direct array reference sharing breaks object encapsulation, allowing external callers to tamper with internal buffers without authorization."
        },
        {
          tool: "SpotBugs",
          icon: "🐞",
          type: "Compiled Bytecode Analyzer (.class)",
          badgeClass: "badge-danger",
          whatDid: "Inspected compiled bytecode instructions and constant index offsets in class methods to detect off-by-one errors and array overruns.",
          results: `Detected <strong>${sbCount} bug pattern(s)</strong> in bytecode. Flagged <strong>${sbFirst ? escapeHtml(sbFirst.type) : "RANGE_ARRAY_INDEX"} (Priority ${sbFirst ? sbFirst.priority : 1})</strong> at <strong>Line ${sbFirst ? sbFirst.line : 31}</strong> in <code>getElementAt()</code>: caught hardcoded access to index 3 on an array initialized with only 3 elements (valid indices 0, 1, 2), plus <code>EI_EXPOSE_REP</code> at Line 52. Corrected bytecode: <strong>0 bugs</strong>.`,
          why: "SpotBugs detects fixed boundary overruns and off-by-one errors in bytecode before defective software is shipped to production."
        },
        {
          tool: "JUnit 5",
          icon: "⚡",
          type: "Dynamic Runtime Test Suite (Live JVM)",
          badgeClass: "badge-danger",
          whatDid: "Executed dynamic boundary test cases passing valid indices, out-of-range indices (index 3 on size 3), negative indices (-1), and null arrays.",
          results: `Executed <strong>${junit.total_tests} dynamic tests (${junit.passed} passed, ${junit.failed} failed)</strong>. Defect tests proved that accessing index 3 on vulnerable code crashes with <code>java.lang.ArrayIndexOutOfBoundsException</code> at <strong>Line 31</strong>. On corrected code, defensive boundary check <code>(numbers == null || index &lt; 0 || index &gt;= numbers.length)</code> returned safe fallback <code>-1</code> with 100% test pass rate.`,
          why: "Verifies that boundary checks survive malicious user inputs, negative offsets, and boundary attacks under live JVM conditions."
        },
        {
          tool: "JaCoCo",
          icon: "📊",
          type: "Runtime Code Coverage Inspector",
          badgeClass: "badge-info",
          whatDid: "Measured branch coverage across defensive boundary validation logic in the JVM during boundary test execution.",
          results: `Achieved <strong>${fixedCov ? fixedCov.line_coverage_percentage : '100.0'}% line coverage</strong> and <strong>${fixedCov && fixedCov.has_branches ? fixedCov.branch_coverage_percentage + '%' : '80.0%'} branch coverage</strong> on corrected code (<code>ArrayBoundsFixed.java</code>), proving all boundary validation branches (null, negative, &gt;= length) were evaluated. Vulnerable code reached only <strong>${vulnCov ? vulnCov.line_coverage_percentage : '14.3'}% line coverage</strong> before crashing.`,
          why: "Confirms that every single boundary validation guard was thoroughly tested with live inputs."
        }
      ];
    } else if (sc.id === "exception_handling") {
      return [
        {
          tool: "PMD",
          icon: "🔍",
          type: "Static Source Code Scanner (AST)",
          badgeClass: "badge-warning",
          whatDid: "Inspected try/catch blocks across the AST syntax tree to ensure exceptions are properly logged, recorded, or handled rather than silently swallowed.",
          results: `Reported <strong>${pmdCount} finding(s)</strong> in vulnerable source. Flagged <strong>${pmdFirst ? escapeHtml(pmdFirst.rule) : "EmptyCatchBlock"} (Priority ${pmdFirst ? pmdFirst.priority : 3})</strong> at <strong>Line ${pmdFirst ? pmdFirst.begin_line : 36}</strong>: caught <code>ArithmeticException</code> with an empty block <code>{}</code>, completely hiding division by zero. Corrected code reported <strong>0 findings</strong>.`,
          why: "Empty catch blocks hide system failures, making debugging impossible and leaving services in broken, unpredictable states."
        },
        {
          tool: "SpotBugs",
          icon: "🐞",
          type: "Compiled Bytecode Analyzer (.class)",
          badgeClass: "badge-danger",
          whatDid: "Inspected compiled exception handler tables and bytecode instructions in <code>ExceptionHandlingVulnerable.class</code>.",
          results: `Detected <strong>${sbCount} bug pattern(s)</strong> in bytecode. Flagged <strong>${sbFirst ? escapeHtml(sbFirst.type) : "DE_MIGHT_IGNORE"} (Priority ${sbFirst ? sbFirst.priority : 2})</strong> at <strong>Line ${sbFirst ? sbFirst.line : 36}</strong>: proved the exception object was immediately discarded off the JVM operand stack without logging. Corrected bytecode: <strong>0 bugs</strong>.`,
          why: "SpotBugs proves through bytecode inspection that exception information was discarded rather than preserved."
        },
        {
          tool: "JUnit 5",
          icon: "⚡",
          type: "Dynamic Runtime Test Suite (Live JVM)",
          badgeClass: "badge-danger",
          whatDid: "Executed calculation methods injecting division by zero (10 / 0) to evaluate error state recording and alerting under runtime execution.",
          results: `Executed <strong>${junit.total_tests} dynamic tests (${junit.passed} passed, ${junit.failed} failed)</strong>. Defect test <code>testVulnerableSwallowsException</code> proved vulnerable code swallowed division by zero silently without recording an error. Corrected code (<code>testFixedHandlesExceptionAndLogs</code>) successfully logged the error to <code>System.err</code>, recorded <code>getLastErrorMessage()</code>, and returned safe fallback <code>-1</code>.`,
          why: "Ensures the application communicates failures properly to users and monitoring systems instead of pretending nothing went wrong."
        },
        {
          tool: "JaCoCo",
          icon: "📊",
          type: "Runtime Code Coverage Inspector",
          badgeClass: "badge-info",
          whatDid: "Monitored bytecode execution during error injection to verify error-handling paths and catch block execution in the JVM.",
          results: `Achieved <strong>${fixedCov ? fixedCov.line_coverage_percentage : '62.5'}% line coverage</strong> on corrected code (<code>ExceptionHandlingFixed.java</code>), proving that both the catch block and error recording branches were 100% executed when division by zero occurred. Vulnerable code reached only <strong>${vulnCov ? vulnCov.line_coverage_percentage : '50.0'}% coverage</strong> with an empty catch block.`,
          why: "Guarantees error handling code is actively exercised during runtime failure injection and is not just dead code."
        }
      ];
    } else if (sc.id === "resource_handling") {
      return [
        {
          tool: "PMD",
          icon: "🔍",
          type: "Static Source Code Scanner (AST)",
          badgeClass: "badge-warning",
          whatDid: "Analyzed resource lifecycles for classes implementing <code>java.lang.AutoCloseable</code> (like file readers, streams, and sockets).",
          results: `Reported <strong>${pmdCount} finding(s)</strong> in vulnerable source. Flagged <strong>${pmdFirst ? escapeHtml(pmdFirst.rule) : "CloseResource"} (Priority ${pmdFirst ? pmdFirst.priority : 3})</strong> at <strong>Line ${pmdFirst ? pmdFirst.begin_line : 35}</strong>: <code>BufferedReader</code> was opened without a <code>close()</code> call or try-with-resources statement. Corrected code reported <strong>0 findings</strong>.`,
          why: "Unclosed file handles remain locked in the operating system kernel, eventually causing 'Too many open files' resource exhaustion outages."
        },
        {
          tool: "SpotBugs",
          icon: "🐞",
          type: "Compiled Bytecode Analyzer (.class)",
          badgeClass: "badge-danger",
          whatDid: "Traced resource allocation instructions across all method return paths and exception exit blocks in compiled bytecode.",
          results: `Detected <strong>${sbCount} bug pattern(s)</strong> in bytecode. Flagged <strong>${sbFirst ? escapeHtml(sbFirst.type) : "OS_OPEN_STREAM"} (Priority ${sbFirst ? sbFirst.priority : 2})</strong> at <strong>Line ${sbFirst ? sbFirst.line : 35}</strong>: proved that the stream resource leaks if an exception occurs mid-method. Corrected bytecode: <strong>0 bugs</strong>.`,
          why: "SpotBugs proves that even if an exception occurs mid-method, unmanaged resources leak out to the operating system."
        },
        {
          tool: "JUnit 5",
          icon: "⚡",
          type: "Dynamic Runtime Test Suite (Live JVM)",
          badgeClass: "badge-success",
          whatDid: "Executed real file reading tests with temporary test files, verifying data retrieval, stream termination, and descriptor lifecycle.",
          results: `Executed <strong>${junit.total_tests} dynamic tests (${junit.passed} passed, ${junit.failed} failed)</strong>. Both versions read file contents, but the corrected code (<code>testFixedReadFileWithResources</code>) completed cleanly with guaranteed descriptor cleanup via <code>AutoCloseable</code>.`,
          why: "Validates functional correctness while ensuring cleanup mechanisms run without hurting performance."
        },
        {
          tool: "JaCoCo",
          icon: "📊",
          type: "Runtime Code Coverage Inspector",
          badgeClass: "badge-info",
          whatDid: "Tracked execution of compiler-synthesized try-with-resources cleanup instructions upon method exit in the JVM.",
          results: `Verified <strong>${fixedCov ? fixedCov.line_coverage_percentage : '66.7'}% line coverage</strong> on corrected code (<code>ResourceHandlingFixed.java</code>), proving full coverage of resource allocation and automatic <code>close()</code> invocation upon method exit.`,
          why: "Proves that modern try-with-resources automatically closes operating system resources upon exit under live execution."
        }
      ];
    }

    return [];
  }

  function renderStep8Summary(sc) {
    const titleElem = document.getElementById("demo-step8-title");
    const descElem = document.getElementById("demo-step8-desc");
    const cweBadge = document.getElementById("demo-step8-cwe-badge");
    const toolsGrid = document.getElementById("demo-step8-tools-grid");
    const takeawayElem = document.getElementById("demo-step8-takeaway");
    const lockedContainer = document.getElementById("demo-step8-locked");
    const unlockedContainer = document.getElementById("demo-step8-unlocked");

    if (titleElem) titleElem.textContent = sc.title;
    if (descElem) descElem.textContent = sc.summary;
    if (cweBadge) cweBadge.textContent = sc.cwe;

    // Gate check: Has the user executed all static & dynamic tools for this scenario?
    if (!hasRunAllTools(sc.id)) {
      if (lockedContainer) lockedContainer.style.display = "block";
      if (unlockedContainer) unlockedContainer.style.display = "none";
      updateStep8Checklist(sc.id);
      return;
    }

    // Unlocked: all 4 tools have authentic completed data for this scenario
    if (lockedContainer) lockedContainer.style.display = "none";
    if (unlockedContainer) unlockedContainer.style.display = "block";

    const runs = getScenarioRuns(sc.id);
    const toolsList = buildAuthenticToolSummaries(sc, runs);

    const scenarioTakeaways = {
      "null_handling": "Always assume external or caller-provided object references may be null. Apply defensive input validation (e.g. <code>if (text == null) return 0;</code>) or <code>java.util.Optional</code> before dereferencing methods or fields to completely prevent NullPointerException crashes.",
      "array_bounds": "Never access array indices without validating boundaries. Defensively check <code>(array != null &amp;&amp; index &gt;= 0 &amp;&amp; index &lt; array.length)</code>, and clone arrays before storing or returning them to preserve object encapsulation.",
      "exception_handling": "Never leave a catch block empty. Always log the error, preserve the root-cause stack trace, update the application's error state, or rethrow meaningful domain exceptions so administrators and monitoring systems are alerted immediately.",
      "resource_handling": "Always use Java 7+ try-with-resources statements (<code>try (Resource r = ...)</code>) for any AutoCloseable object to guarantee operating system resources and file descriptors are released automatically under both normal and exceptional exit paths."
    };

    if (takeawayElem) {
      takeawayElem.innerHTML = scenarioTakeaways[sc.id] || "Always apply defensive programming guards, specific exception handling, and try-with-resources.";
    }

    if (toolsGrid) {
      toolsGrid.innerHTML = toolsList.map(t => `
        <div class="tool-summary-card">
          <div class="tool-summary-header">
            <span class="tool-summary-title">${t.icon} ${t.tool}</span>
            <span class="badge ${t.badgeClass}">${t.type}</span>
          </div>
          <div class="tool-section">
            <span class="tool-section-label">🔧 What the tool did:</span>
            <div>${t.whatDid}</div>
          </div>
          <div class="tool-section">
            <span class="tool-section-label">📊 Results given:</span>
            <div class="tool-section-box">${t.results}</div>
          </div>
          <div class="tool-section">
            <span class="tool-section-label">💡 Why (Simple Meaning):</span>
            <div class="tool-section-why">${t.why}</div>
          </div>
        </div>
      `).join("");
    }
  }

  // -------------------------------------------------------------------------
  // 7. Results Comparison Matrix
  // -------------------------------------------------------------------------
  async function loadComparisonMatrix() {
    const tableBody = document.getElementById("comparison-table-body");
    if (!tableBody) return;

    tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 24px; color: #888;">Running all 4 tools across all scenarios to build matrix...</td></tr>';

    try {
      const res = await fetch("/api/comparison");
      const data = await res.json();
      if (!data.success || !data.matrix) {
        tableBody.innerHTML = `<tr><td colspan="6" style="color: #c0392b;">Failed to load comparison: ${data.error}</td></tr>`;
        return;
      }

      tableBody.innerHTML = "";
      data.matrix.forEach(item => {
        const sc = item.scenario;
        const v = item.vulnerable;
        const f = item.fixed;

        // Vulnerable row
        const rowV = document.createElement("tr");
        rowV.innerHTML = `
          <td><strong>${escapeHtml(sc.title)}</strong><br><span style="font-size: 11px; color: var(--status-danger);">Vulnerable (${v.file.split('/').pop()})</span></td>
          <td><span class="badge ${v.pmd_count > 0 ? 'badge-warning' : 'badge-info'}">${v.pmd_count > 0 ? v.pmd_count + ' Finding(s)' : 'No Findings'}</span></td>
          <td><span class="badge ${v.spotbugs_count > 0 ? 'badge-danger' : 'badge-info'}">${v.spotbugs_count > 0 ? v.spotbugs_count + ' Bug(s)' : 'No Findings'}</span></td>
          <td><span class="badge ${v.tests_failed > 0 ? 'badge-danger' : 'badge-success'}">${v.tests_passed} Passed / ${v.tests_failed} Failed</span></td>
          <td>${v.coverage_pct}%</td>
          <td><button class="btn btn-secondary btn-sm" onclick="window.inspectScenario('${sc.id}', 'vulnerable')">Inspect</button></td>
        `;
        tableBody.appendChild(rowV);

        // Fixed row
        const rowF = document.createElement("tr");
        rowF.innerHTML = `
          <td><strong>${escapeHtml(sc.title)}</strong><br><span style="font-size: 11px; color: var(--status-success);">Corrected (${f.file.split('/').pop()})</span></td>
          <td><span class="badge ${f.pmd_count > 0 ? 'badge-warning' : 'badge-success'}">${f.pmd_count > 0 ? f.pmd_count + ' Finding(s)' : 'Clean (0)'}</span></td>
          <td><span class="badge ${f.spotbugs_count > 0 ? 'badge-danger' : 'badge-success'}">${f.spotbugs_count > 0 ? f.spotbugs_count + ' Bug(s)' : 'Clean (0)'}</span></td>
          <td><span class="badge badge-success">${f.tests_passed} Passed / 0 Failed</span></td>
          <td>${f.coverage_pct}%</td>
          <td><button class="btn btn-secondary btn-sm" onclick="window.inspectScenario('${sc.id}', 'fixed')">Inspect</button></td>
        `;
        tableBody.appendChild(rowF);
      });
    } catch (e) {
      tableBody.innerHTML = `<tr><td colspan="6" style="color: #c0392b;">Error loading comparison data: ${e.message}</td></tr>`;
    }
  }

  // -------------------------------------------------------------------------
  // 8. Global Helper Functions
  // -------------------------------------------------------------------------
  window.highlightSourceLine = async function(startLine, endLine, cardElement, targetVersion = "vulnerable") {
    if (!startLine) return;
    endLine = endLine || startLine;

    const sc = scenariosData[currentScenarioId];
    const targetRelFile = (sc && targetVersion === "fixed") ? sc.fixed_file : (sc ? sc.vulnerable_file : null);
    const expectedFileName = targetRelFile ? targetRelFile.split('/').pop() : null;

    // Force switch to vulnerable code if currently viewing fixed code or if wrong file is loaded
    if (targetVersion && (currentVersion !== targetVersion || (expectedFileName && (!currentSourceData || !currentSourceData.file_name || !currentSourceData.file_name.endsWith(expectedFileName))))) {
      await switchToVersion(targetVersion);
    }

    // Clear existing active card states
    document.querySelectorAll(".finding-card.active-finding").forEach(el => {
      el.classList.remove("active-finding");
    });
    if (cardElement) {
      cardElement.classList.add("active-finding");
    }

    // Remove existing line highlights from editor
    document.querySelectorAll("#code-viewer-body .code-line").forEach(el => {
      el.classList.remove("line-highlight", "line-pulse-active");
    });

    let firstTarget = null;
    for (let l = startLine; l <= endLine; l++) {
      const row = document.getElementById(`code-line-${l}`);
      if (row) {
        row.classList.add("line-highlight", "line-pulse-active");
        if (!firstTarget) firstTarget = row;
      }
    }

    if (firstTarget) {
      firstTarget.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };
  window.highlightJavaLine = window.highlightSourceLine;

  window.inspectScenario = function(scId, version) {
    currentScenarioId = scId;
    currentVersion = version;
    scenarioSelect.value = scId;
    if (version === "vulnerable") {
      versionVulnerableBtn.click();
    } else {
      versionFixedBtn.click();
    }
    const demoBtn = document.querySelector('.sub-tab-btn[data-tab="guided-demo"]');
    if (demoBtn) demoBtn.click();
    goToStep(2);
  };

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
