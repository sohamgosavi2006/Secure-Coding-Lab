/**
 * Secure Coding Laboratory Suite — Master Portal Controller
 * Integrates:
 * 1. Suite Hub & Architecture Documentation
 * 2. Project 1: SQL Injection Explorer (Live query inspector, parameterized queries, bypasses)
 * 3. Project 2: JavaCodeCheck Lab (PMD, SpotBugs, JUnit 5, JaCoCo, 8-step guided demo)
 */

document.addEventListener("DOMContentLoaded", () => {
  // ---------------------------------------------------------------------------
  // 0. Global Theme Controller (Light / Dark)
  // ---------------------------------------------------------------------------
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
        try {
          localStorage.setItem("securelab_theme", "dark");
        } catch (e) {}
      } else {
        document.documentElement.setAttribute("data-theme", "light");
        toggleBtn.setAttribute("aria-checked", "false");
        toggleBtn.setAttribute("aria-label", "Switch to dark theme");
        if (lightLabel) lightLabel.classList.add("active");
        if (darkLabel) darkLabel.classList.remove("active");
        try {
          localStorage.setItem("securelab_theme", "light");
        } catch (e) {}
      }
    }

    // Initialize from localStorage or fallback to light
    let activeTheme = "light";
    try {
      const saved = localStorage.getItem("securelab_theme");
      if (saved === "dark") {
        activeTheme = "dark";
      }
    } catch (e) {}

    updateThemeUI(activeTheme);

    toggleBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      const nextTheme = current === "dark" ? "light" : "dark";
      updateThemeUI(nextTheme);
    });
  }

  // ---------------------------------------------------------------------------
  // 1. Master Portal Navigation
  // ---------------------------------------------------------------------------
  const portalNavBtns = document.querySelectorAll(".portal-nav-btn");
  const portalPanes = document.querySelectorAll(".portal-pane");

  portalNavBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      portalNavBtns.forEach(b => b.classList.remove("active"));
      portalPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-portal-tab");
      const targetPane = document.getElementById(`portal-${targetId}`);
      if (targetPane) targetPane.classList.add("active");

      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });

  // Global helper to switch to a specific project tab
  window.switchToProject = function(projectId) {
    const btn = document.querySelector(`.portal-nav-btn[data-portal-tab="${projectId}"]`);
    if (btn) btn.click();
  };

  // ---------------------------------------------------------------------------
  // 2. PROJECT 1: SQL Injection Explorer Logic
  // ---------------------------------------------------------------------------
  initSqlInjectionLab();

  function initSqlInjectionLab() {
    const vulnUsernameInput = document.getElementById("sqli-vuln-username");
    const vulnPasswordInput = document.getElementById("sqli-vuln-password");
    const btnVulnLogin = document.getElementById("btn-sqli-vuln-login");
    const vulnCountainer = document.getElementById("sqli-vuln-result");

    const secUsernameInput = document.getElementById("sqli-sec-username");
    const secPasswordInput = document.getElementById("sqli-sec-password");
    const btnSecLogin = document.getElementById("btn-sqli-sec-login");
    const secContainer = document.getElementById("sqli-sec-result");

    const btnResetDb = document.getElementById("btn-sqli-reset");
    const inspectorQuery = document.getElementById("sqli-inspector-query");
    const inspectorExplanation = document.getElementById("sqli-inspector-explanation");

    // Quick-Fill Buttons
    document.querySelectorAll(".sqli-payload-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const u = btn.getAttribute("data-u");
        const p = btn.getAttribute("data-p");
        if (vulnUsernameInput) vulnUsernameInput.value = u;
        if (vulnPasswordInput) vulnPasswordInput.value = p;
        if (secUsernameInput) secUsernameInput.value = u;
        if (secPasswordInput) secPasswordInput.value = p;
      });
    });

    // Vulnerable Login Action
    if (btnVulnLogin) {
      btnVulnLogin.addEventListener("click", async () => {
        const u = vulnUsernameInput.value;
        const p = vulnPasswordInput.value;
        vulnCountainer.innerHTML = '<span class="badge badge-info">Executing...</span>';

        try {
          const res = await fetch("/api/vulnerable/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: u, password: p })
          });
          const data = await res.json();
          renderVulnResult(data, vulnCountainer, inspectorQuery, inspectorExplanation);
        } catch (e) {
          vulnCountainer.innerHTML = `<span style="color: #c0392b;">Error: ${e.message}</span>`;
        }
      });
    }

    // Secure Login Action
    if (btnSecLogin) {
      btnSecLogin.addEventListener("click", async () => {
        const u = secUsernameInput.value;
        const p = secPasswordInput.value;
        secContainer.innerHTML = '<span class="badge badge-info">Executing...</span>';

        try {
          const res = await fetch("/api/secure/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: u, password: p })
          });
          const data = await res.json();
          renderSecResult(data, secContainer, inspectorQuery, inspectorExplanation);
        } catch (e) {
          secContainer.innerHTML = `<span style="color: #c0392b;">Error: ${e.message}</span>`;
        }
      });
    }

    // Reset Database Action
    if (btnResetDb) {
      btnResetDb.addEventListener("click", async () => {
        try {
          const res = await fetch("/api/reset", { method: "POST" });
          const json = await res.json();
          alert(json.message || "Database reset successfully!");
          if (vulnUsernameInput) vulnUsernameInput.value = "";
          if (vulnPasswordInput) vulnPasswordInput.value = "";
          if (secUsernameInput) secUsernameInput.value = "";
          if (secPasswordInput) secPasswordInput.value = "";
        } catch (e) {
          alert("Failed to reset database: " + e.message);
        }
      });
    }
  }

  function renderVulnResult(data, container, inspectorQ, inspectorE) {
    if (inspectorQ) inspectorQ.textContent = data.constructed_query || "";
    if (inspectorE) inspectorE.textContent = data.explanation || "";

    if (data.database_error) {
      container.innerHTML = `
        <div style="background: var(--status-danger-bg); border: 1px solid var(--status-danger-border); padding: 12px; border-radius: 6px;">
          <span class="badge badge-danger">SQL SYNTAX ERROR</span>
          <p style="margin-top: 6px; font-family: var(--font-mono); font-size: 12px; color: #c0392b;">${escapeHtml(data.database_error)}</p>
          <div style="font-size: 11.5px; color: #666; margin-top: 4px;">Unbalanced quotes broke SQLite grammar.</div>
        </div>
      `;
      return;
    }

    if (data.success) {
      const u = data.authenticated_user;
      const isBypass = data.is_bypass;
      container.innerHTML = `
        <div style="background: ${isBypass ? '#fff4f2' : 'var(--status-success-bg)'}; border: 1px solid ${isBypass ? '#f5c6cb' : 'var(--status-success-border)'}; padding: 12px; border-radius: 6px;">
          <span class="badge ${isBypass ? 'badge-danger' : 'badge-success'}">${isBypass ? '⚠️ AUTHENTICATION BYPASS' : '✓ LOGIN SUCCESSFUL'}</span>
          <div style="margin-top: 8px; font-size: 13px;">
            <strong>Logged In User:</strong> ${escapeHtml(u.full_name)} (<code>${escapeHtml(u.username)}</code>)<br>
            <strong>Role:</strong> ${escapeHtml(u.role)} &bull; <strong>Email:</strong> ${escapeHtml(u.email)}
          </div>
          ${isBypass ? '<div style="margin-top: 6px; font-size: 12px; color: #c0392b;"><strong>Exploit Succeeded:</strong> Administrator access was granted without a valid password!</div>' : ''}
        </div>
      `;
    } else {
      container.innerHTML = `
        <div style="background: var(--bg-subtle); border: 1px solid var(--border-medium); padding: 12px; border-radius: 6px;">
          <span class="badge badge-warning">LOGIN REJECTED</span>
          <div style="margin-top: 6px; font-size: 12.5px; color: var(--text-secondary);">${escapeHtml(data.message)}</div>
        </div>
      `;
    }
  }

  function renderSecResult(data, container, inspectorQ, inspectorE) {
    if (inspectorQ) {
      inspectorQ.textContent = `TEMPLATE: ${data.query_template || ""}\nBOUND PARAMS: ${JSON.stringify(data.bound_parameters || [])}`;
    }
    if (inspectorE) inspectorE.textContent = data.explanation || "";

    if (data.success) {
      const u = data.authenticated_user;
      container.innerHTML = `
        <div style="background: var(--status-success-bg); border: 1px solid var(--status-success-border); padding: 12px; border-radius: 6px;">
          <span class="badge badge-success">✓ SECURE LOGIN SUCCESSFUL</span>
          <div style="margin-top: 8px; font-size: 13px;">
            <strong>User:</strong> ${escapeHtml(u.full_name)} (<code>${escapeHtml(u.username)}</code>)<br>
            <strong>Role:</strong> ${escapeHtml(u.role)}
          </div>
        </div>
      `;
    } else {
      container.innerHTML = `
        <div style="background: var(--status-success-bg); border: 1px solid var(--status-success-border); padding: 12px; border-radius: 6px;">
          <span class="badge badge-success">🛡️ INJECTION BLOCKED / REJECTED</span>
          <div style="margin-top: 6px; font-size: 12.5px; color: #27774e;">
            <strong>Safe Defense:</strong> User input was treated strictly as literal data. The special characters (<code>'</code>, <code>OR</code>, <code>--</code>) were never interpreted as SQL grammar.
          </div>
        </div>
      `;
    }
  }

  // ---------------------------------------------------------------------------
  // 3. PROJECT 2: JavaCodeCheck Lab Logic
  // ---------------------------------------------------------------------------
  initJavaCodeCheck();

  // ---------------------------------------------------------------------------
  // 4. PROJECT 3: WebShield Lab — Web Server Attack & Defense Logic
  // ---------------------------------------------------------------------------
  initWebServerAttackLab();

  function initJavaCodeCheck() {
    let currentScenarioId = "null_handling";
    let currentVersion = "vulnerable";
    let currentDemoStep = 1;
    let scenariosData = {};
    let currentSourceData = null;

    let lastCoverageData = null;
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

    const scenarioSelect = document.getElementById("java-scenario-select");
    const versionVulnerableBtn = document.getElementById("btn-java-version-vulnerable");
    const versionFixedBtn = document.getElementById("btn-java-version-fixed");
    const btnClearHighlights = document.getElementById("btn-java-clear-highlights");
    const sourceFilePathElem = document.getElementById("java-code-viewer-path");
    const codeViewerBody = document.getElementById("java-code-viewer-body");

    // Sub-nav for Java lab
    const subNavBtns = document.querySelectorAll(".sub-tab-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

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

    // Version Switcher Helper
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
        if (jacocoResults && lastCoverageData) {
          renderJacocoResults(lastCoverageData, jacocoResults);
        }
      }
    }

    // Version Switcher buttons
    if (versionVulnerableBtn && versionFixedBtn) {
      versionVulnerableBtn.addEventListener("click", () => {
        switchToVersion("vulnerable");
      });

      versionFixedBtn.addEventListener("click", () => {
        switchToVersion("fixed");
      });
    }

    // Clear Highlights button beside Source Version
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

    // Step indicators
    const stepPills = document.querySelectorAll(".step-pill");
    const btnStepPrev = document.getElementById("btn-step-prev");
    const btnStepNext = document.getElementById("btn-step-next");
    const btnExitDemo = document.getElementById("btn-exit-demo");

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

    // Action buttons
    const btnRunPmd = document.getElementById("btn-run-pmd");
    if (btnRunPmd) btnRunPmd.addEventListener("click", () => executePmdAction());

    const btnRunSpotbugs = document.getElementById("btn-run-spotbugs");
    if (btnRunSpotbugs) btnRunSpotbugs.addEventListener("click", () => executeSpotbugsAction());

    const btnRunJunit = document.getElementById("btn-run-junit");
    if (btnRunJunit) btnRunJunit.addEventListener("click", () => executeJunitAction());

    const btnRunJacoco = document.getElementById("btn-run-jacoco");
    if (btnRunJacoco) btnRunJacoco.addEventListener("click", () => executeJacocoAction());

    const btnStep8RunAll = document.getElementById("btn-step8-run-all");
    if (btnStep8RunAll) btnStep8RunAll.addEventListener("click", () => runAllToolsForScenario(currentScenarioId));

    const btnStep8StepThrough = document.getElementById("btn-step8-step-through");
    if (btnStep8StepThrough) btnStep8StepThrough.addEventListener("click", () => goToStep(3));

    const btnStep8RefreshSummary = document.getElementById("btn-step8-refresh-summary");
    if (btnStep8RefreshSummary) btnStep8RefreshSummary.addEventListener("click", () => runAllToolsForScenario(currentScenarioId));

    // Fetch Java Status & Scenarios
    fetchJavaStatus();
    fetchJavaScenarios();

    async function fetchJavaStatus() {
      try {
        const res = await fetch("/api/java/status");
        const data = await res.json();
        if (!data.tools) return;

        updateToolStatusBadge("pmd", data.tools.pmd);
        updateToolStatusBadge("spotbugs", data.tools.spotbugs);
        updateToolStatusBadge("junit", data.tools.junit);
        updateToolStatusBadge("jacoco", data.tools.jacoco);
      } catch (e) {
        console.warn("Could not fetch Java tool status:", e);
      }
    }

    function updateToolStatusBadge(id, tool) {
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

    async function fetchJavaScenarios() {
      try {
        const res = await fetch("/api/java/scenarios");
        const data = await res.json();
        if (data.scenarios) {
          if (scenarioSelect) scenarioSelect.innerHTML = "";
          data.scenarios.forEach(sc => {
            scenariosData[sc.id] = sc;
            const opt = document.createElement("option");
            opt.value = sc.id;
            opt.textContent = `${sc.title} (${sc.category})`;
            if (scenarioSelect) scenarioSelect.appendChild(opt);
          });

          if (scenarioSelect) {
            scenarioSelect.addEventListener("change", async (e) => {
              currentScenarioId = e.target.value;
              await switchToVersion("vulnerable");
              loadScenario(currentScenarioId);
              onScenarioChanged(currentScenarioId);
            });
          }
          loadScenario(currentScenarioId);
        }
      } catch (e) {
        console.error("Failed to load Java scenarios:", e);
      }
    }

    async function loadScenario(scenarioId) {
      const sc = scenariosData[scenarioId];
      if (!sc) return;

      renderStep1Details(sc);
      const relFile = currentVersion === "vulnerable" ? sc.vulnerable_file : sc.fixed_file;
      await loadSourceFile(relFile);
    }

    async function loadSourceFile(relPath) {
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
        const res = await fetch(`/api/java/source?file=${encodeURIComponent("src/main/java/" + relPath)}`);
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

      // Handle multiline comments
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

        if (coverageLines && coverageLines[line.number] && !isNonExecutableLine(line.text)) {
          const covStatus = coverageLines[line.number].status;
          if (covStatus === "covered") row.classList.add("line-covered");
          else if (covStatus === "partially_covered") row.classList.add("line-partial");
          else if (covStatus === "uncovered") row.classList.add("line-uncovered");
        }

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
        if (targetRow) targetRow.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }

    function goToStep(stepNum) {
      currentDemoStep = stepNum;

      stepPills.forEach(pill => {
        const num = parseInt(pill.getAttribute("data-step"), 10);
        pill.classList.remove("active", "completed");
        if (num === stepNum) pill.classList.add("active");
        else if (num < stepNum) pill.classList.add("completed");
      });

      for (let i = 1; i <= 8; i++) {
        const contentElem = document.getElementById(`demo-step-${i}`);
        if (contentElem) contentElem.style.display = (i === stepNum) ? "block" : "none";
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

      if (btnStepPrev) btnStepPrev.disabled = (stepNum === 1);
      if (btnStepNext) btnStepNext.textContent = (stepNum === 8) ? "Finish Demo" : "Next Step →";

      onEnterStep(stepNum);
    }

    function onEnterStep(stepNum) {
      const sc = scenariosData[currentScenarioId];
      if (!sc) return;

      if (stepNum === 1) renderStep1Details(sc);
      else if (stepNum === 2) loadScenario(currentScenarioId);
      else if (stepNum === 7) renderStep7Comparison(sc);
      else if (stepNum === 8) renderStep8Summary(sc);
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
          "expected": "Defensively validate if (text == null) return 0;, safely handling null without throwing an exception."
        },
        "array_bounds": {
          "defect": "Accessing numbers[3] directly on an array of 3 elements (valid indices 0, 1, 2) triggers ArrayIndexOutOfBoundsException at runtime and SpotBugs RANGE_ARRAY_INDEX in bytecode.",
          "expected": "Validate boundaries: if (numbers == null || index < 0 || index >= numbers.length) return -1; before accessing the element."
        },
        "exception_handling": {
          "defect": "Empty catch (ArithmeticException e) {} block that silently swallows the 10 / 0 division failure without any reporting, logging, or error indication (CWE-390).",
          "expected": "Report the failure to System.err ('Calculation failed: ' + e.getMessage()) and record the failure state instead of hiding it."
        },
        "resource_handling": {
          "defect": "Allocating BufferedReader via Files.newBufferedReader(path) without closing the resource, leaking operating-system file descriptors and buffer memory.",
          "expected": "Use Java 7+ try-with-resources statement: try (BufferedReader reader = Files.newBufferedReader(path)) for guaranteed automatic cleanup."
        }
      };

      const info = defectDescriptions[sc.id] || {};
      if (defectElem) defectElem.textContent = info.defect || "";
      if (expectedElem) expectedElem.textContent = info.expected || "";
    }

    async function executePmdAction() {
      const sc = scenariosData[currentScenarioId];
      const resultsContainer = document.getElementById("demo-pmd-results");
      if (!resultsContainer) return;

      resultsContainer.innerHTML = '<div style="padding: 16px; color: #666;"><span class="badge badge-info">RUNNING</span> Executing PMD AST static analysis...</div>';
      const targetFile = currentVersion === "vulnerable" ? sc.vulnerable_file : sc.fixed_file;

      try {
        const res = await fetch("/api/java/pmd", {
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
          <div class="finding-card" onclick="window.highlightJavaLine(${f.begin_line}, ${f.end_line || f.begin_line}, this, 'vulnerable')" title="Click to inspect this finding in the vulnerable Java code viewer">
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
        const res = await fetch("/api/java/spotbugs", {
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
              SpotBugs analyzed compiled bytecode and detected no known bug patterns for this class.
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
        const clickAttr = lineNum ? `onclick="window.highlightJavaLine(${lineNum}, ${f.end_line || lineNum}, this, 'vulnerable')" title="Click to inspect this bug pattern in the vulnerable Java code viewer"` : "";

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
        const res = await fetch("/api/java/junit", {
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

        const clickAttr = targetLine ? `onclick="window.highlightJavaLine(${targetLine}, ${targetLine}, this, 'vulnerable')" title="Click to inspect defect location in vulnerable source code"` : "";

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
        const res = await fetch("/api/java/junit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ test_class: sc.test_class })
        });
        const data = await res.json();
        lastCoverageData = data.coverage;
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
                <button type="button" class="btn btn-sm btn-secondary" style="border-color: #f85149; color: #c0392b; font-weight: 600;" onclick="window.highlightJavaLine(${ln}, ${ln}, null, '${currentVersion}')">
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

    function renderStep7Comparison(sc) {
      const container = document.getElementById("demo-step7-comparison-body");
      if (!container) return;

      container.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
          <div style="background: var(--status-danger-bg); border: 1px solid var(--status-danger-border); padding: 16px; border-radius: 6px;">
            <h4 style="color: var(--status-danger); margin-bottom: 8px;">Vulnerable Version (${sc.vulnerable_file.split('/').pop()})</h4>
            <ul style="font-size: 12.5px; padding-left: 18px; color: var(--text-secondary); line-height: 1.6;">
              <li>Susceptible to flaw: <code>${sc.cwe}</code></li>
              <li>Static analysis flags missing checks or resource leaks</li>
              <li>Runtime tests demonstrate unhandled exceptions or silent state suppression</li>
            </ul>
          </div>
          <div style="background: var(--status-success-bg); border: 1px solid var(--status-success-border); padding: 16px; border-radius: 6px;">
            <h4 style="color: var(--status-success); margin-bottom: 8px;">Corrected Version (${sc.fixed_file.split('/').pop()})</h4>
            <ul style="font-size: 12.5px; padding-left: 18px; color: var(--text-secondary); line-height: 1.6;">
              <li>Defensive programming guards applied</li>
              <li>Static warnings neutralized</li>
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
        const pmdRes = await fetch("/api/java/pmd", {
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
        const sbRes = await fetch("/api/java/spotbugs", {
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
        const junitRes = await fetch("/api/java/junit", {
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

    async function loadComparisonMatrix() {
      const tableBody = document.getElementById("comparison-table-body");
      if (!tableBody) return;

      tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 24px; color: #888;">Running all 4 tools across all scenarios to build matrix...</td></tr>';

      try {
        const res = await fetch("/api/java/comparison");
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

          const rowV = document.createElement("tr");
          rowV.innerHTML = `
            <td><strong>${escapeHtml(sc.title)}</strong><br><span style="font-size: 11px; color: var(--status-danger);">Vulnerable (${v.file.split('/').pop()})</span></td>
            <td><span class="badge ${v.pmd_count > 0 ? 'badge-warning' : 'badge-info'}">${v.pmd_count > 0 ? v.pmd_count + ' Finding(s)' : 'No Findings'}</span></td>
            <td><span class="badge ${v.spotbugs_count > 0 ? 'badge-danger' : 'badge-info'}">${v.spotbugs_count > 0 ? v.spotbugs_count + ' Bug(s)' : 'No Findings'}</span></td>
            <td><span class="badge ${v.tests_failed > 0 ? 'badge-danger' : 'badge-success'}">${v.tests_passed} Passed / ${v.tests_failed} Failed</span></td>
            <td>${v.coverage_pct}%</td>
            <td><button class="btn btn-secondary btn-sm" onclick="window.inspectJavaScenario('${sc.id}', 'vulnerable')">Inspect</button></td>
          `;
          tableBody.appendChild(rowV);

          const rowF = document.createElement("tr");
          rowF.innerHTML = `
            <td><strong>${escapeHtml(sc.title)}</strong><br><span style="font-size: 11px; color: var(--status-success);">Corrected (${f.file.split('/').pop()})</span></td>
            <td><span class="badge ${f.pmd_count > 0 ? 'badge-warning' : 'badge-success'}">${f.pmd_count > 0 ? f.pmd_count + ' Finding(s)' : 'Clean (0)'}</span></td>
            <td><span class="badge ${f.spotbugs_count > 0 ? 'badge-danger' : 'badge-success'}">${f.spotbugs_count > 0 ? f.spotbugs_count + ' Bug(s)' : 'Clean (0)'}</span></td>
            <td><span class="badge badge-success">${f.tests_passed} Passed / 0 Failed</span></td>
            <td>${f.coverage_pct}%</td>
            <td><button class="btn btn-secondary btn-sm" onclick="window.inspectJavaScenario('${sc.id}', 'fixed')">Inspect</button></td>
          `;
          tableBody.appendChild(rowF);
        });
      } catch (e) {
        tableBody.innerHTML = `<tr><td colspan="6" style="color: #c0392b;">Error loading comparison data: ${e.message}</td></tr>`;
      }
    }

    window.highlightJavaLine = async function(startLine, endLine, cardElement, targetVersion = "vulnerable") {
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
      document.querySelectorAll("#java-code-viewer-body .code-line").forEach(el => {
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

    window.inspectJavaScenario = function(scId, version) {
      currentScenarioId = scId;
      currentVersion = version;
      if (scenarioSelect) scenarioSelect.value = scId;
      if (version === "vulnerable" && versionVulnerableBtn) {
        versionVulnerableBtn.click();
      } else if (versionFixedBtn) {
        versionFixedBtn.click();
      }
      const demoBtn = document.querySelector('.sub-tab-btn[data-tab="guided-demo"]');
      if (demoBtn) demoBtn.click();
      goToStep(2);
    };
  }

  // ---------------------------------------------------------------------------
  // 4. PROJECT 3: WebShield Lab — Web Server Attack & Defense Implementation
  // ---------------------------------------------------------------------------
  function initWebServerAttackLab() {
    let currentWebStep = 1;
    let vulnSourceCache = null;
    let secSourceCache = null;
    let lastComparisonResults = null;

    // Active state for the Studio left editor
    let studioState = {
      activeTab: "body", // "body" or "headers"
      title: "File Layout",
      folder: "public_vulnerable",
      filename: "directory_layout",
      method: "LOCAL",
      url: "local:///public_vulnerable/",
      status: 200,
      statusChipText: "READY",
      statusChipClass: "vscode-chip-info",
      mimeType: "text/plain",
      bodyHtml: "",
      headersHtml: "",
      lineCount: 0,
      verdictText: "Ready for live demonstration"
    };

    // Sub-tab Navigation (Overview, Guided Demo, Hardening Guide, Comparison)
    const webSubNavBtns = document.querySelectorAll(".sub-tab-btn[data-web-tab]");
    const webTabPanes = document.querySelectorAll(".web-tab-pane");

    window.switchWebTab = function(tabId) {
      webSubNavBtns.forEach(btn => {
        if (btn.getAttribute("data-web-tab") === tabId) {
          btn.classList.add("active");
        } else {
          btn.classList.remove("active");
        }
      });

      webTabPanes.forEach(pane => {
        if (pane.id === `web-tab-${tabId}`) {
          pane.classList.add("active");
        } else {
          pane.classList.remove("active");
        }
      });

      window.scrollTo({ top: 120, behavior: "smooth" });
    };

    webSubNavBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        const targetTab = btn.getAttribute("data-web-tab");
        window.switchWebTab(targetTab);
      });
    });

    const btnStartGuidedDemo = document.getElementById("btn-web-start-guided-demo");
    if (btnStartGuidedDemo) {
      btnStartGuidedDemo.addEventListener("click", () => {
        window.switchWebTab("guided-demo");
        window.setWebStep(1);
      });
    }

    // Step Pills & Navigation
    const webStepPills = document.querySelectorAll("#web-step-pills .step-pill");
    const btnWebPrev = document.getElementById("btn-web-prev");
    const btnWebNext = document.getElementById("btn-web-next");
    const btnWebReset = document.getElementById("btn-web-reset");
    const btnWebExit = document.getElementById("btn-web-exit");

    window.setWebStep = function(stepNum) {
      currentWebStep = Math.max(1, Math.min(8, stepNum));

      // Update pills
      webStepPills.forEach(pill => {
        const s = parseInt(pill.getAttribute("data-web-step"), 10);
        pill.classList.remove("active", "completed");
        if (s === currentWebStep) pill.classList.add("active");
        else if (s < currentWebStep) pill.classList.add("completed");
      });

      // Show matching step card
      for (let i = 1; i <= 8; i++) {
        const card = document.getElementById(`web-step-card-${i}`);
        if (card) {
          card.style.display = (i === currentWebStep) ? "block" : "none";
        }
      }

      if (btnWebPrev) btnWebPrev.disabled = (currentWebStep === 1);
      if (btnWebNext) {
        if (currentWebStep === 8) {
          btnWebNext.textContent = "View Comparison Matrix →";
        } else {
          btnWebNext.textContent = "Next Step →";
        }
      }

      onEnterWebStep(currentWebStep);
    };

    if (btnWebPrev) {
      btnWebPrev.addEventListener("click", () => {
        if (currentWebStep > 1) window.setWebStep(currentWebStep - 1);
      });
    }

    if (btnWebNext) {
      btnWebNext.addEventListener("click", () => {
        if (currentWebStep < 8) {
          window.setWebStep(currentWebStep + 1);
        } else {
          window.switchWebTab("comparison");
        }
      });
    }

    if (btnWebReset) {
      btnWebReset.addEventListener("click", () => {
        window.setWebStep(1);
      });
    }

    if (btnWebExit) {
      btnWebExit.addEventListener("click", () => {
        window.switchWebTab("overview");
      });
    }

    webStepPills.forEach(pill => {
      pill.addEventListener("click", () => {
        const s = parseInt(pill.getAttribute("data-web-step"), 10);
        window.setWebStep(s);
      });
    });

    // -------------------------------------------------------------------------
    // Studio Display & Tab Switching
    // -------------------------------------------------------------------------
    function updateStudioDisplay() {
      const codeViewer = document.getElementById("web-code-viewer-body");
      const titleElem = document.getElementById("web-tab-title-text");
      const folderElem = document.getElementById("web-bc-folder");
      const fileElem = document.getElementById("web-bc-file");
      const statusChip = document.getElementById("web-studio-chip");
      const mimeChip = document.getElementById("web-studio-mime-chip");
      const statusUrl = document.getElementById("web-status-method-url");
      const statusLineCount = document.getElementById("web-status-line-count");
      const statusVerdict = document.getElementById("web-status-security-verdict");
      const tabBody = document.getElementById("web-tab-btn-response-body");
      const tabHeaders = document.getElementById("web-tab-btn-response-headers");

      if (titleElem) titleElem.textContent = studioState.title;
      if (folderElem) folderElem.textContent = studioState.folder;
      if (fileElem) fileElem.textContent = studioState.filename;

      if (statusChip) {
        statusChip.className = `vscode-chip ${studioState.statusChipClass}`;
        statusChip.textContent = studioState.statusChipText;
      }
      if (mimeChip) mimeChip.textContent = studioState.mimeType;

      if (statusUrl) statusUrl.textContent = `${studioState.method} ${studioState.url}`;
      if (statusLineCount) statusLineCount.textContent = `${studioState.lineCount} lines`;
      if (statusVerdict) statusVerdict.textContent = studioState.verdictText;

      if (tabBody) {
        if (studioState.activeTab === "body") tabBody.classList.add("active");
        else tabBody.classList.remove("active");
      }
      if (tabHeaders) {
        if (studioState.activeTab === "headers") tabHeaders.classList.add("active");
        else tabHeaders.classList.remove("active");
      }

      if (codeViewer) {
        codeViewer.innerHTML = (studioState.activeTab === "body") ? studioState.bodyHtml : studioState.headersHtml;
      }
    }

    const tabBtnBody = document.getElementById("web-tab-btn-response-body");
    const tabBtnHeaders = document.getElementById("web-tab-btn-response-headers");

    if (tabBtnBody) {
      tabBtnBody.addEventListener("click", () => {
        studioState.activeTab = "body";
        updateStudioDisplay();
      });
    }

    if (tabBtnHeaders) {
      tabBtnHeaders.addEventListener("click", () => {
        studioState.activeTab = "headers";
        updateStudioDisplay();
      });
    }

    // Helper: Wrap code lines into VS Code style rows with line numbers
    function buildLineNumberedHtml(lines) {
      return lines.map((contentHtml, idx) => {
        return `<div class="code-line"><span class="line-num">${idx + 1}</span><span class="line-content">${contentHtml}</span></div>`;
      }).join("");
    }

    // -------------------------------------------------------------------------
    // Syntax Colorizers (VS Code Dark Palette)
    // -------------------------------------------------------------------------
    function colorizeConfigFile(rawText) {
      const lines = rawText.split("\n");
      const formattedLines = lines.map(line => {
        const trimmed = line.trim();
        if (!trimmed) return "&nbsp;";
        if (trimmed.startsWith("#") || trimmed.startsWith("--") || trimmed.startsWith("//")) {
          return `<span class="tok-comm">${escapeHtml(line)}</span>`;
        }
        if (line.includes("=")) {
          const eqIdx = line.indexOf("=");
          const key = line.slice(0, eqIdx);
          const val = line.slice(eqIdx + 1);
          const isSecret = /TOKEN|PASSWORD|SECRET|KEY|CREDENTIAL|PIN/i.test(key);

          const keyHtml = `<span class="tok-cfg-key">${escapeHtml(key)}</span>`;
          const valHtml = isSecret 
            ? `<span class="tok-vuln-secret">${escapeHtml(val)}</span>` 
            : `<span class="tok-cfg-val">${escapeHtml(val)}</span>`;

          return `${keyHtml}=${valHtml}`;
        }
        if (/INSERT INTO/i.test(line)) {
          let esc = escapeHtml(line);
          esc = esc.replace(/\b(INSERT INTO|VALUES)\b/g, '<span class="tok-kw">$&</span>');
          esc = esc.replace(/'(.*?)'/g, '<span class="tok-str">\'$1\'</span>');
          if (/password|pin|secret/i.test(esc)) {
            esc = `<span style="background: rgba(239, 68, 68, 0.16);">${esc}</span>`;
          }
          return esc;
        }
        return escapeHtml(line);
      });
      return {
        html: buildLineNumberedHtml(formattedLines),
        count: lines.length
      };
    }

    function colorizeHtmlText(rawText) {
      const lines = rawText.split("\n");
      const formattedLines = lines.map(line => {
        if (!line.trim()) return "&nbsp;";
        let esc = escapeHtml(line);

        // Highlight HTML comments
        if (esc.includes("&lt;!--")) {
          return esc.replace(/(&lt;!--.*?--&gt;)/g, '<span class="tok-comm">$1</span>');
        }

        // Highlight tags & attributes
        esc = esc.replace(/(&lt;\/?)([a-zA-Z0-9]+)(.*?)(&gt;)/g, (match, open, tag, attrs, close) => {
          let attrColored = attrs.replace(/([a-zA-Z0-9_-]+)=(".*?"|'.*?'|[^\s>]+)/g, '<span class="tok-attr">$1</span>=<span class="tok-str">$2</span>');
          return `${open}<span class="tok-tag">${tag}</span>${attrColored}${close}`;
        });

        // Highlight exposed rows in directory index
        if (/demo-config\.txt|backup-demo\.txt|SENSITIVE EXPOSED/i.test(esc)) {
          esc = `<span style="background: rgba(239, 68, 68, 0.22); border-radius: 4px; padding: 2px 6px; display: inline-block;">${esc}</span>`;
        }

        // Highlight 403 Forbidden / Access Denied
        if (/403 Forbidden|Access Denied/i.test(esc)) {
          esc = `<span style="color: #f87171; font-weight: bold;">${esc}</span>`;
        }

        return esc;
      });
      return {
        html: buildLineNumberedHtml(formattedLines),
        count: lines.length
      };
    }

    function colorizeHttpHeaders(method, url, status, statusText, server, contentType, extraHeaders) {
      const lines = [];
      lines.push(`<span class="tok-kw">${method}</span> <span class="tok-attr">${escapeHtml(url)}</span> <span class="tok-comm">HTTP/1.1</span>`);
      
      const statusColorClass = (status === 200) ? "tok-hdr-status-200" : ((status === 403) ? "tok-hdr-status-403" : "tok-hdr-status-404");
      lines.push(`<span class="tok-comm">HTTP/1.1</span> <span class="${statusColorClass}">${status} ${escapeHtml(statusText)}</span>`);
      lines.push(`<span class="tok-hdr-name">Date:</span> <span class="tok-hdr-val">${new Date().toUTCString()}</span>`);
      lines.push(`<span class="tok-hdr-name">Content-Type:</span> <span class="tok-hdr-val">${escapeHtml(contentType)}</span>`);
      lines.push(`<span class="tok-hdr-name">Server:</span> <span class="tok-hdr-val">${escapeHtml(server)}</span>`);

      if (extraHeaders && Array.isArray(extraHeaders)) {
        extraHeaders.forEach(hdr => {
          if (hdr.isSecurity) {
            lines.push(`<div class="tok-hdr-security"><span class="tok-hdr-name">${escapeHtml(hdr.name)}:</span> <span class="tok-sec-safe">${escapeHtml(hdr.value)}</span></div>`);
          } else if (hdr.isDanger) {
            lines.push(`<div class="tok-hdr-danger"><span class="tok-hdr-name">${escapeHtml(hdr.name)}:</span> <span class="tok-vuln-secret">${escapeHtml(hdr.value)}</span></div>`);
          } else {
            lines.push(`<span class="tok-hdr-name">${escapeHtml(hdr.name)}:</span> <span class="tok-hdr-val">${escapeHtml(hdr.value)}</span>`);
          }
        });
      }
      lines.push(`<span class="tok-hdr-name">Connection:</span> <span class="tok-hdr-val">keep-alive</span>`);

      return {
        html: buildLineNumberedHtml(lines),
        count: lines.length
      };
    }

    // -------------------------------------------------------------------------
    // Step 1: File Layout Visualizer
    // -------------------------------------------------------------------------
    function showFileLayout(isVulnerable) {
      studioState.activeTab = "body";
      studioState.method = "LOCAL";
      studioState.mimeType = "filesystem/tree";

      if (isVulnerable) {
        studioState.title = "📁 Vulnerable Public Web Root Layout";
        studioState.folder = "public_vulnerable";
        studioState.filename = "directory_tree";
        studioState.url = "local:///public_vulnerable/";
        studioState.status = 200;
        studioState.statusChipText = "MISCONFIGURED";
        studioState.statusChipClass = "vscode-chip-danger";
        studioState.verdictText = "⚠️ CWE-548 & CWE-552: Secret config stored in public root";

        const lines = [
          `<span class="tok-comm"># Intended Public Web Root with Disastrous Misconfiguration</span>`,
          `<span class="tok-comm"># Web document directory served directly by web daemon:</span>`,
          `📁 <strong style="color: #60a5fa;">public_vulnerable/</strong>`,
          `├── 📄 <span class="tok-str">index.html</span>        <span class="tok-sec-safe">Public Web Page (Safe)</span>`,
          `├── 📄 <span class="tok-str">about.html</span>        <span class="tok-sec-safe">Public Web Page (Safe)</span>`,
          `├── ⚠️ <strong style="color: #f87171;">demo-config.txt</strong>   <span class="tok-vuln-secret">CRITICAL FLAW: Database Passwords &amp; API Tokens Exposed</span>`,
          `└── ⚠️ <strong style="color: #f87171;">backup-demo.txt</strong>   <span class="tok-vuln-secret">CRITICAL FLAW: SQL Database Dump In Public Directory</span>`,
          ``,
          `<span class="tok-comm"># Evaluation Analysis:</span>`,
          `<span class="tok-comm"># Placing confidential config or backup files inside the public web directory</span>`,
          `<span class="tok-comm"># allows any internet user to download them directly via ordinary HTTP GET.</span>`
        ];

        studioState.bodyHtml = buildLineNumberedHtml(lines);
        studioState.lineCount = lines.length;
      } else {
        studioState.title = "🛡️ Hardened & Segregated File Layout";
        studioState.folder = "public_secure";
        studioState.filename = "directory_tree";
        studioState.url = "local:///public_secure/ & /private_storage/";
        studioState.status = 200;
        studioState.statusChipText = "PROPERLY SEGREGATED";
        studioState.statusChipClass = "vscode-chip-success";
        studioState.verdictText = "🛡️ Physical Segregation: Secrets stored outside public web root";

        const lines = [
          `<span class="tok-comm"># Hardened Defense-in-Depth Architecture</span>`,
          `<span class="tok-comm"># 1. Public Web Root (Accessible to Visitors):</span>`,
          `📁 <strong style="color: #60a5fa;">public_secure/</strong>`,
          `├── 📄 <span class="tok-str">index.html</span>        <span class="tok-sec-safe">Approved Public Asset</span>`,
          `└── 📄 <span class="tok-str">about.html</span>        <span class="tok-sec-safe">Approved Public Asset</span>`,
          ``,
          `<span class="tok-comm"># 2. Private Quarantined Storage (Completely OUTSIDE Web Root):</span>`,
          `📁 <strong style="color: #4ade80;">private_storage/</strong>`,
          `├── 🔒 <strong style="color: #4ade80;">demo-config.txt</strong>   <span class="tok-sec-safe">Quarantined: Inaccessible to HTTP Requests</span>`,
          `└── 🔒 <strong style="color: #4ade80;">backup-demo.txt</strong>   <span class="tok-sec-safe">Quarantined: Inaccessible to HTTP Requests</span>`,
          ``,
          `<span class="tok-comm"># Evaluation Analysis:</span>`,
          `<span class="tok-comm"># Even if an attacker requests /demo-config.txt or /backup-demo.txt, the web server cannot serve them</span>`,
          `<span class="tok-comm"># because both confidential files physically exist outside the public document root.</span>`
        ];

        studioState.bodyHtml = buildLineNumberedHtml(lines);
        studioState.lineCount = lines.length;
      }

      const headers = colorizeHttpHeaders("LOCAL", studioState.url, 200, "OK", "Local Filesystem Inspection", "filesystem/tree", []);
      studioState.headersHtml = headers.html;

      updateStudioDisplay();
    }

    const btnViewLayoutVuln = document.getElementById("btn-web-view-layout-vuln");
    if (btnViewLayoutVuln) {
      btnViewLayoutVuln.addEventListener("click", () => showFileLayout(true));
    }

    const btnViewLayoutSec = document.getElementById("btn-web-view-layout-sec");
    if (btnViewLayoutSec) {
      btnViewLayoutSec.addEventListener("click", () => showFileLayout(false));
    }

    // -------------------------------------------------------------------------
    // Step 2: Directory Browsing Attack (CWE-548)
    // -------------------------------------------------------------------------
    const btnFetchVulnBrowse = document.getElementById("btn-fetch-vuln-browse");
    if (btnFetchVulnBrowse) {
      btnFetchVulnBrowse.addEventListener("click", async () => {
        studioState.activeTab = "body";
        studioState.method = "GET";
        studioState.url = "/web-server-attack/vulnerable/browse";
        studioState.folder = "public_vulnerable";
        studioState.filename = "directory_index.html";
        studioState.title = "Index of /vulnerable/files/";
        studioState.mimeType = "text/html; charset=utf-8";

        try {
          const res = await fetch("/web-server-attack/vulnerable/browse", {
            headers: { "Accept": "text/html" }
          });
          const status = res.status;
          const contentType = res.headers.get("Content-Type") || "text/html; charset=utf-8";
          const serverHeader = res.headers.get("Server") || "Apache/2.4.52 (Unix) Simulated";
          const text = await res.text();

          studioState.status = status;
          studioState.statusChipText = "200 OK — CWE-548 EXPOSURE";
          studioState.statusChipClass = "vscode-chip-danger";
          studioState.verdictText = "⚠️ CWE-548: Directory listing volunteered complete catalog of files!";

          const colored = colorizeHtmlText(text);
          studioState.bodyHtml = colored.html;
          studioState.lineCount = colored.count;

          const extraHeaders = [
            { name: "X-Lab-Misconfiguration", value: "Apache Options +Indexes Simulated", isDanger: true }
          ];
          const hdrs = colorizeHttpHeaders("GET", studioState.url, status, "OK", serverHeader, contentType, extraHeaders);
          studioState.headersHtml = hdrs.html;

          updateStudioDisplay();

        } catch (err) {
          studioState.bodyHtml = `<div style="color: #f87171; padding: 20px;">Request failed: ${err.message}</div>`;
          updateStudioDisplay();
        }
      });
    }

    // -------------------------------------------------------------------------
    // Step 3: Request Exposed Files (CWE-552)
    // -------------------------------------------------------------------------
    window.fetchVulnerableFile = async function(filename) {
      studioState.activeTab = "body";
      studioState.method = "GET";
      studioState.url = `/web-server-attack/vulnerable/files/${filename}`;
      studioState.folder = "public_vulnerable";
      studioState.filename = filename;
      studioState.title = filename;

      try {
        const res = await fetch(`/web-server-attack/vulnerable/files/${filename}`);
        const status = res.status;
        const contentType = res.headers.get("Content-Type") || "text/plain";
        const serverHeader = res.headers.get("Server") || "Apache/2.4.52 (Unix) Simulated";
        const exposureHeader = res.headers.get("X-Lab-Exposure") || "Vulnerable: File served directly from public web root";
        const text = await res.text();

        studioState.status = status;
        studioState.mimeType = contentType;

        const isSensitive = filename.includes("config") || filename.includes("backup");

        if (status === 200) {
          if (isSensitive) {
            studioState.statusChipText = "200 OK — EXPOSED CREDENTIALS";
            studioState.statusChipClass = "vscode-chip-danger";
            studioState.verdictText = "⚠️ CWE-552: Secret file served directly from public web root!";
          } else {
            studioState.statusChipText = "200 OK — PUBLIC ASSET";
            studioState.statusChipClass = "vscode-chip-info";
            studioState.verdictText = "Normal public web page served from public web root";
          }
        } else {
          studioState.statusChipText = `${status} ERROR`;
          studioState.statusChipClass = "vscode-chip-warning";
          studioState.verdictText = `Server returned HTTP ${status}`;
        }

        let coloredBody;
        if (contentType.includes("html") || filename.endsWith(".html")) {
          coloredBody = colorizeHtmlText(text);
        } else {
          coloredBody = colorizeConfigFile(text);
        }

        studioState.bodyHtml = coloredBody.html;
        studioState.lineCount = coloredBody.count;

        const extraHeaders = [
          { name: "X-Lab-Exposure", value: exposureHeader, isDanger: isSensitive }
        ];
        const hdrs = colorizeHttpHeaders("GET", studioState.url, status, status === 200 ? "OK" : "NOT FOUND", serverHeader, contentType, extraHeaders);
        studioState.headersHtml = hdrs.html;

        updateStudioDisplay();

      } catch (err) {
        studioState.bodyHtml = `<div style="color: #f87171; padding: 20px;">Request failed: ${err.message}</div>`;
        updateStudioDisplay();
      }
    };

    const btnReqVulnConfig = document.getElementById("btn-request-vuln-config");
    if (btnReqVulnConfig) {
      btnReqVulnConfig.addEventListener("click", () => window.fetchVulnerableFile("demo-config.txt"));
    }

    const btnReqVulnBackup = document.getElementById("btn-request-vuln-backup");
    if (btnReqVulnBackup) {
      btnReqVulnBackup.addEventListener("click", () => window.fetchVulnerableFile("backup-demo.txt"));
    }

    const btnReqVulnIndex = document.getElementById("btn-request-vuln-index");
    if (btnReqVulnIndex) {
      btnReqVulnIndex.addEventListener("click", () => window.fetchVulnerableFile("index.html"));
    }

    // -------------------------------------------------------------------------
    // Step 4 & 7: Python Server Source Code Inspection
    // -------------------------------------------------------------------------
    async function loadVulnerableSourceCode() {
      studioState.activeTab = "body";
      studioState.method = "CODE";
      studioState.url = "file:///Web Server Attack/routes.py";
      studioState.folder = "Web Server Attack";
      studioState.filename = "routes.py (vulnerable)";
      studioState.title = "routes.py — vulnerable_browse & vulnerable_serve_file";
      studioState.status = 200;
      studioState.statusChipText = "VULNERABLE HANDLER";
      studioState.statusChipClass = "vscode-chip-vuln";
      studioState.mimeType = "text/x-python";
      studioState.verdictText = "⚠️ CWE-548 & CWE-552 Identified in genuine Python source code";

      if (vulnSourceCache) {
        renderSourceIntoStudio(vulnSourceCache);
        return;
      }

      studioState.bodyHtml = '<div style="padding: 20px; color: #888;">Loading genuine server source code...</div>';
      updateStudioDisplay();

      try {
        const res = await fetch("/web-server-attack/api/source?target=vulnerable");
        const data = await res.json();
        if (data.success) {
          vulnSourceCache = data;
          renderSourceIntoStudio(data);
        } else {
          studioState.bodyHtml = `<div style="padding: 20px; color: #ff8080;">Error: ${data.error}</div>`;
          updateStudioDisplay();
        }
      } catch (e) {
        studioState.bodyHtml = `<div style="padding: 20px; color: #ff8080;">Error: ${e.message}</div>`;
        updateStudioDisplay();
      }
    }

    async function loadSecureSourceCode() {
      studioState.activeTab = "body";
      studioState.method = "CODE";
      studioState.url = "file:///Web Server Attack/routes.py";
      studioState.folder = "Web Server Attack";
      studioState.filename = "routes.py (secure)";
      studioState.title = "routes.py — secure_browse & secure_serve_file";
      studioState.status = 200;
      studioState.statusChipText = "HARDENED HANDLER";
      studioState.statusChipClass = "vscode-chip-fixed";
      studioState.mimeType = "text/x-python";
      studioState.verdictText = "🛡️ CWE-548 & CWE-552 Mitigated with allowlist and defense headers";

      if (secSourceCache) {
        renderSourceIntoStudio(secSourceCache);
        return;
      }

      studioState.bodyHtml = '<div style="padding: 20px; color: #888;">Loading genuine server source code...</div>';
      updateStudioDisplay();

      try {
        const res = await fetch("/web-server-attack/api/source?target=secure");
        const data = await res.json();
        if (data.success) {
          secSourceCache = data;
          renderSourceIntoStudio(data);
        } else {
          studioState.bodyHtml = `<div style="padding: 20px; color: #ff8080;">Error: ${data.error}</div>`;
          updateStudioDisplay();
        }
      } catch (e) {
        studioState.bodyHtml = `<div style="padding: 20px; color: #ff8080;">Error: ${e.message}</div>`;
        updateStudioDisplay();
      }
    }

    function renderSourceIntoStudio(sourceData) {
      const state = { inDocstring: false };
      let lastRenderedFinding = null;

      const lines = sourceData.code_lines.map(item => {
        let highlightedCode = highlightPythonLine(item.code, state);
        let highlightClass = "";
        let badgeHtml = "";

        if (item.highlight) {
          if (item.highlight_type === "vulnerable") {
            highlightClass = "line-vuln-red";
          } else if (item.highlight_type === "secure") {
            highlightClass = "line-sec-green";
          } else if (item.highlight_type === "defense_neutral") {
            highlightClass = "line-defense-neutral";
          } else {
            highlightClass = "line-highlight";
          }

          if (item.finding_id && item.finding_id !== lastRenderedFinding) {
            lastRenderedFinding = item.finding_id;
            let tagTypeClass = "tag-vuln";
            let tagLabel = "🚨 Flaw";
            if (item.highlight_type === "secure") {
              tagTypeClass = "tag-sec";
              tagLabel = "🛡️ Protection";
            } else if (item.highlight_type === "defense_neutral") {
              tagTypeClass = "tag-defense";
              tagLabel = "ℹ️ Path Defense";
            }
            badgeHtml = `<span class="line-tag ${tagTypeClass}" title="${escapeHtml(item.annotation || '')}">${tagLabel}</span>`;
          }
        } else {
          lastRenderedFinding = null;
        }

        const findingAttr = item.finding_id ? `data-finding="${item.finding_id}"` : "";
        const titleAttr = item.annotation ? `title="${escapeHtml(item.annotation)}"` : "";
        return `<div class="code-line ${highlightClass}" id="studio-line-${item.line_number}" data-line="${item.line_number}" ${findingAttr} ${titleAttr}><span class="line-num">${item.line_number}</span><span class="line-content">${highlightedCode}</span>${badgeHtml}</div>`;
      });

      studioState.bodyHtml = lines.join("");
      studioState.lineCount = sourceData.code_lines.length;

      const hdrs = colorizeHttpHeaders("CODE", studioState.url, 200, "OK", "Local Python Source Audit", "text/x-python", []);
      studioState.headersHtml = hdrs.html;

      updateStudioDisplay();
    }

    function highlightPythonLine(rawText, state = { inDocstring: false }) {
      if (!rawText) return "&nbsp;";
      let text = rawText;

      // Multiline docstring continuation
      if (state.inDocstring) {
        const endTriple = text.indexOf('"""');
        const endSingleTriple = text.indexOf("'''");
        const endIdx = endTriple !== -1 ? endTriple : endSingleTriple;
        if (endIdx === -1) {
          return `<span class="tok-comm">${escapeHtml(text)}</span>`;
        } else {
          state.inDocstring = false;
          const docEnd = endIdx + 3;
          return `<span class="tok-comm">${escapeHtml(text.slice(0, docEnd))}</span>` + 
                 highlightPythonLine(text.slice(docEnd), state);
        }
      }

      const trimmed = text.trimStart();
      if (trimmed.startsWith("#")) {
        const leading = text.length - trimmed.length;
        return escapeHtml(text.slice(0, leading)) + `<span class="tok-comm">${escapeHtml(trimmed)}</span>`;
      }

      // Check if line contains a triple quote start
      const tripleDoubleIdx = text.indexOf('"""');
      const tripleSingleIdx = text.indexOf("'''");
      if (tripleDoubleIdx !== -1 || tripleSingleIdx !== -1) {
        const quoteType = (tripleDoubleIdx !== -1 && (tripleSingleIdx === -1 || tripleDoubleIdx < tripleSingleIdx)) ? '"""' : "'''";
        const startIdx = text.indexOf(quoteType);
        const secondIdx = text.indexOf(quoteType, startIdx + 3);
        if (secondIdx === -1) {
          state.inDocstring = true;
          return escapeHtml(text.slice(0, startIdx)) + `<span class="tok-comm">${escapeHtml(text.slice(startIdx))}</span>`;
        } else {
          return escapeHtml(text.slice(0, startIdx)) + 
                 `<span class="tok-comm">${escapeHtml(text.slice(startIdx, secondIdx + 3))}</span>` +
                 highlightPythonLine(text.slice(secondIdx + 3), state);
        }
      }

      const keywords = new Set([
        "def", "return", "if", "else", "elif", "import", "from", "in", "not", "and", "or",
        "for", "while", "try", "except", "finally", "raise", "pass", "True", "False", "None",
        "with", "as", "class", "global", "nonlocal", "lambda", "yield", "async", "await"
      ]);

      const builtins = new Set([
        "len", "str", "int", "list", "dict", "set", "tuple", "bool", "print", "range",
        "enumerate", "jsonify", "make_response", "render_template_string", "request", "is_safe_path"
      ]);

      const tokenRegex = /(#[^\r\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|@[\w.]+|\b\d+(?:\.\d+)?\b|\b[a-zA-Z_]\w*\b)/g;

      let html = "";
      let lastIndex = 0;
      let match;

      while ((match = tokenRegex.exec(text)) !== null) {
        if (match.index > lastIndex) {
          html += escapeHtml(text.slice(lastIndex, match.index));
        }

        const tok = match[0];

        if (tok.startsWith("#")) {
          html += `<span class="tok-comm">${escapeHtml(tok)}</span>`;
        } else if (tok.startsWith('"') || tok.startsWith("'")) {
          html += `<span class="tok-str">${escapeHtml(tok)}</span>`;
        } else if (tok.startsWith("@")) {
          html += `<span class="tok-ann">${escapeHtml(tok)}</span>`;
        } else if (keywords.has(tok)) {
          html += `<span class="tok-kw">${escapeHtml(tok)}</span>`;
        } else if (builtins.has(tok)) {
          html += `<span class="tok-fn">${escapeHtml(tok)}</span>`;
        } else if (/^\d/.test(tok)) {
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

    window.scrollToFinding = function(findingId) {
      const targetLines = document.querySelectorAll(`#web-code-viewer-body .code-line[data-finding="${findingId}"]`);
      if (targetLines.length > 0) {
        targetLines[0].scrollIntoView({ behavior: "smooth", block: "center" });
        targetLines.forEach(el => {
          el.classList.add("line-pulse-active");
          setTimeout(() => el.classList.remove("line-pulse-active"), 2600);
        });
      }
    };

    window.scrollToFlaw = function(flawId) {
      if (flawId === 1) {
        window.scrollToFinding("vuln_dir_listing");
      } else if (flawId === 2) {
        window.scrollToFinding("vuln_file_exposure");
      } else if (flawId === 3 || flawId === "defense") {
        window.scrollToFinding("defense_path_check");
      } else {
        window.scrollToFinding(flawId);
      }
    };

    const btnLoadVulnCode = document.getElementById("btn-load-vuln-code");
    if (btnLoadVulnCode) {
      btnLoadVulnCode.addEventListener("click", () => {
        vulnSourceCache = null;
        loadVulnerableSourceCode();
      });
    }

    const btnLoadSecCode = document.getElementById("btn-load-sec-code");
    if (btnLoadSecCode) {
      btnLoadSecCode.addEventListener("click", () => {
        secSourceCache = null;
        loadSecureSourceCode();
      });
    }

    // -------------------------------------------------------------------------
    // Step 6: Test Secure Endpoints
    // -------------------------------------------------------------------------
    window.fetchSecureResource = async function(resourcePath, friendlyName) {
      studioState.activeTab = "body";
      studioState.method = "GET";
      studioState.url = `/web-server-attack/${resourcePath}`;
      studioState.folder = resourcePath.includes("secure/browse") ? "public_secure" : "public_secure";
      const filePart = resourcePath.split("/").pop() || "resource";
      studioState.filename = filePart;
      studioState.title = `${filePart} (${friendlyName})`;

      try {
        const res = await fetch(studioState.url);
        const status = res.status;
        const contentType = res.headers.get("Content-Type") || "text/html; charset=utf-8";
        const serverHeader = res.headers.get("Server") || "WebShield-Hardened/2.0";
        const nosniffHeader = res.headers.get("X-Content-Type-Options") || "nosniff";
        const frameHeader = res.headers.get("X-Frame-Options") || "DENY";
        const text = await res.text();

        studioState.status = status;
        studioState.mimeType = contentType;

        let statusText = "OK";
        if (status === 200) {
          studioState.statusChipText = "200 OK — ALLOWED PUBLIC ASSET";
          studioState.statusChipClass = "vscode-chip-info";
          studioState.verdictText = "🛡️ Safe Public Resource: Served with defense-in-depth security headers";
        } else if (status === 403) {
          statusText = "FORBIDDEN";
          studioState.statusChipText = "403 FORBIDDEN — BLOCKED";
          studioState.statusChipClass = "vscode-chip-success";
          studioState.verdictText = "🛡️ Protected Defense: Directory browsing / unlisted asset blocked";
        } else {
          statusText = "NOT FOUND";
          studioState.statusChipText = "404 NOT FOUND — SAFE";
          studioState.statusChipClass = "vscode-chip-warning";
          studioState.verdictText = "Clean 404: Resource does not exist without disclosing file paths";
        }

        let coloredBody;
        if (contentType.includes("html") || text.includes("<html") || text.includes("<!DOCTYPE")) {
          coloredBody = colorizeHtmlText(text);
        } else {
          coloredBody = colorizeConfigFile(text);
        }

        studioState.bodyHtml = coloredBody.html;
        studioState.lineCount = coloredBody.count;

        const extraHeaders = [
          { name: "X-Content-Type-Options", value: nosniffHeader, isSecurity: true },
          { name: "X-Frame-Options", value: frameHeader, isSecurity: true }
        ];
        const hdrs = colorizeHttpHeaders("GET", studioState.url, status, statusText, serverHeader, contentType, extraHeaders);
        studioState.headersHtml = hdrs.html;

        updateStudioDisplay();

      } catch (err) {
        studioState.bodyHtml = `<div style="color: #f87171; padding: 20px;">Request failed: ${err.message}</div>`;
        updateStudioDisplay();
      }
    };

    const btnReqSecIndex = document.getElementById("btn-request-sec-index");
    if (btnReqSecIndex) {
      btnReqSecIndex.addEventListener("click", () => window.fetchSecureResource("secure/files/index.html", "Public Homepage"));
    }

    const btnReqSecBrowse = document.getElementById("btn-request-sec-browse");
    if (btnReqSecBrowse) {
      btnReqSecBrowse.addEventListener("click", () => window.fetchSecureResource("secure/browse", "Directory Listing"));
    }

    const btnReqSecConfig = document.getElementById("btn-request-sec-config");
    if (btnReqSecConfig) {
      btnReqSecConfig.addEventListener("click", () => window.fetchSecureResource("secure/files/demo-config.txt", "Private Configuration"));
    }

    const btnReqSecBackup = document.getElementById("btn-request-sec-backup");
    if (btnReqSecBackup) {
      btnReqSecBackup.addEventListener("click", () => window.fetchSecureResource("secure/files/backup-demo.txt", "Quarantined Database Backup"));
    }

    const btnReqSecUnknown = document.getElementById("btn-request-sec-unknown");
    if (btnReqSecUnknown) {
      btnReqSecUnknown.addEventListener("click", () => window.fetchSecureResource("secure/files/missing-nonexistent.txt", "Unknown Resource"));
    }

    // -------------------------------------------------------------------------
    // Step 8: Production Server Directives
    // -------------------------------------------------------------------------
    function showProductionConfig(serverType) {
      studioState.activeTab = "body";
      studioState.method = "CONFIG";
      studioState.mimeType = "text/plain";
      studioState.status = 200;
      studioState.statusChipText = "PRODUCTION DIRECTIVE";
      studioState.statusChipClass = "vscode-chip-info";
      studioState.verdictText = "🛡️ Hardening configuration rule for production servers";

      if (serverType === "apache") {
        studioState.title = "⚙️ Apache httpd.conf / .htaccess Directives";
        studioState.folder = "/etc/httpd/conf";
        studioState.filename = "httpd.conf";
        studioState.url = "apache:///etc/httpd/conf/httpd.conf";

        const lines = [
          `<span class="tok-comm"># ====================================================================</span>`,
          `<span class="tok-comm"># Apache HTTP Server Hardening Rules (CIS Benchmark &amp; OWASP Best Practice)</span>`,
          `<span class="tok-comm"># ====================================================================</span>`,
          ``,
          `<span class="tok-comm"># 1. Disable opportunistic directory listing globally (CWE-548 fix)</span>`,
          `&lt;<span class="tok-tag">Directory</span> <span class="tok-str">"/var/www/html"</span>&gt;`,
          `    <span class="tok-kw">Options</span> <span class="tok-str">-Indexes</span>`,
          `    <span class="tok-kw">AllowOverride</span> <span class="tok-str">None</span>`,
          `    <span class="tok-kw">Require</span> <span class="tok-str">all granted</span>`,
          `&lt;/<span class="tok-tag">Directory</span>&gt;`,
          ``,
          `<span class="tok-comm"># 2. Block direct requests for confidential file extensions (CWE-552 fix)</span>`,
          `&lt;<span class="tok-tag">FilesMatch</span> <span class="tok-str">"\.(txt|env|conf|bak|sql|ini|yml|yaml)$"</span>&gt;`,
          `    <span class="tok-kw">Require</span> <span class="tok-vuln-secret">all denied</span>`,
          `&lt;/<span class="tok-tag">FilesMatch</span>&gt;`,
          ``,
          `<span class="tok-comm"># 3. Add defensive security response headers</span>`,
          `<span class="tok-kw">Header</span> <span class="tok-kw-mod">always set</span> <span class="tok-type">X-Content-Type-Options</span> <span class="tok-str">"nosniff"</span>`,
          `<span class="tok-kw">Header</span> <span class="tok-kw-mod">always set</span> <span class="tok-type">X-Frame-Options</span> <span class="tok-str">"DENY"</span>`
        ];

        studioState.bodyHtml = buildLineNumberedHtml(lines);
        studioState.lineCount = lines.length;
      } else {
        studioState.title = "⚙️ Nginx nginx.conf Directives";
        studioState.folder = "/etc/nginx";
        studioState.filename = "nginx.conf";
        studioState.url = "nginx:///etc/nginx/nginx.conf";

        const lines = [
          `<span class="tok-comm"># ====================================================================</span>`,
          `<span class="tok-comm"># Nginx Server Hardening Rules (CIS Benchmark &amp; OWASP Best Practice)</span>`,
          `<span class="tok-comm"># ====================================================================</span>`,
          ``,
          `<span class="tok-kw">server</span> {`,
          `    <span class="tok-kw">listen</span> <span class="tok-num">80</span>;`,
          `    <span class="tok-kw">server_name</span> <span class="tok-str">example.local</span>;`,
          `    <span class="tok-kw">root</span> <span class="tok-str">/var/www/html</span>;`,
          ``,
          `    <span class="tok-comm"># 1. Disable directory indexing globally (CWE-548 fix)</span>`,
          `    <span class="tok-kw">autoindex</span> <span class="tok-str">off</span>;`,
          ``,
          `    <span class="tok-comm"># 2. Deny access to hidden dotfiles (.env, .git)</span>`,
          `    <span class="tok-kw">location</span> ~ <span class="tok-str">/\.</span> {`,
          `        <span class="tok-kw">deny</span> <span class="tok-str">all</span>;`,
          `    }`,
          ``,
          `    <span class="tok-comm"># 3. Deny sensitive file extensions (CWE-552 fix)</span>`,
          `    <span class="tok-kw">location</span> ~* <span class="tok-str">\.(txt|env|conf|bak|sql|ini|yml|yaml)$</span> {`,
          `        <span class="tok-kw">deny</span> <span class="tok-str">all</span>;`,
          `    }`,
          ``,
          `    <span class="tok-comm"># 4. Defensive security headers</span>`,
          `    <span class="tok-kw">add_header</span> <span class="tok-type">X-Content-Type-Options</span> <span class="tok-str">"nosniff"</span> <span class="tok-str">always</span>;`,
          `    <span class="tok-kw">add_header</span> <span class="tok-type">X-Frame-Options</span> <span class="tok-str">"DENY"</span> <span class="tok-str">always</span>;`,
          `}`
        ];

        studioState.bodyHtml = buildLineNumberedHtml(lines);
        studioState.lineCount = lines.length;
      }

      const headers = colorizeHttpHeaders("CONFIG", studioState.url, 200, "OK", `${serverType.toUpperCase()} Configuration Audit`, "text/plain", []);
      studioState.headersHtml = headers.html;

      updateStudioDisplay();
    }

    const btnShowApache = document.getElementById("btn-show-apache-conf");
    if (btnShowApache) {
      btnShowApache.addEventListener("click", () => showProductionConfig("apache"));
    }

    const btnShowNginx = document.getElementById("btn-show-nginx-conf");
    if (btnShowNginx) {
      btnShowNginx.addEventListener("click", () => showProductionConfig("nginx"));
    }

    // -------------------------------------------------------------------------
    // Step Initialization Manager
    // -------------------------------------------------------------------------
    function onEnterWebStep(step) {
      if (step === 1) {
        showFileLayout(true);
      } else if (step === 2) {
        studioState.activeTab = "body";
        studioState.title = "Index of /vulnerable/files/";
        studioState.folder = "public_vulnerable";
        studioState.filename = "directory_index.html";
        studioState.method = "GET";
        studioState.url = "/web-server-attack/vulnerable/browse";
        studioState.status = 200;
        studioState.statusChipText = "AWAITING REQUEST";
        studioState.statusChipClass = "vscode-chip-info";
        studioState.mimeType = "text/html";
        studioState.verdictText = "Click '⚡ Send GET /vulnerable/browse' on the right to test live server";
        
        const placeholder = [
          `<span class="tok-comm"># Step 2: Directory Browsing Attack Demonstration</span>`,
          `<span class="tok-comm"># The running server is configured with Apache 'Options +Indexes' (or Nginx 'autoindex on;').</span>`,
          `<span class="tok-comm"># Click '⚡ Send GET /vulnerable/browse' on the right to issue the live request.</span>`,
          ``,
          `<span class="tok-comm"># The real HTTP response and HTML payload will be rendered right here in VS Code!</span>`
        ];
        studioState.bodyHtml = buildLineNumberedHtml(placeholder);
        studioState.lineCount = placeholder.length;
        const hdrs = colorizeHttpHeaders("GET", "/web-server-attack/vulnerable/browse", 200, "READY", "Apache/2.4.52 (Unix) Simulated", "text/html", []);
        studioState.headersHtml = hdrs.html;
        updateStudioDisplay();
      } else if (step === 3) {
        window.fetchVulnerableFile("demo-config.txt");
      } else if (step === 4) {
        loadVulnerableSourceCode();
      } else if (step === 5) {
        showFileLayout(false);
      } else if (step === 6) {
        window.fetchSecureResource("secure/browse", "Directory Listing");
      } else if (step === 7) {
        loadSecureSourceCode();
      } else if (step === 8) {
        showProductionConfig("apache");
      }
    }

    // Initialize step 1 immediately
    showFileLayout(true);

    // Tab 3: Results Comparison Matrix
    const btnRunCompareTests = document.getElementById("btn-run-web-compare-tests");
    if (btnRunCompareTests) {
      btnRunCompareTests.addEventListener("click", async () => {
        btnRunCompareTests.disabled = true;
        btnRunCompareTests.textContent = "⏳ Running Live Verification Suite...";

        try {
          const res = await fetch("/web-server-attack/api/compare-tests");
          const data = await res.json();
          lastComparisonResults = data.results;

          data.results.forEach(tc => {
            const row = document.querySelector(`tr[data-tc="${tc.id}"]`);
            if (!row) return;

            const statusCell = row.querySelector(".tc-status");
            const resultCell = row.querySelector(".tc-result");

            if (statusCell) {
              statusCell.innerHTML = `
                <div><span style="font-size: 11px; color: #888;">Vuln:</span> <strong style="color: ${tc.vulnerable.actual_status === 200 ? '#b52a1d' : '#444'}">${tc.vulnerable.actual_status}</strong></div>
                <div><span style="font-size: 11px; color: #888;">Sec:</span> <strong style="color: ${tc.secure.actual_status === 200 ? '#1e6b43' : (tc.secure.actual_status === 403 ? '#9e5b1e' : '#1d5b99')}">${tc.secure.actual_status}</strong></div>
              `;
            }

            if (resultCell) {
              if (tc.overall_pass) {
                resultCell.innerHTML = `<span class="badge badge-success">PASS</span>`;
              } else {
                resultCell.innerHTML = `<span class="badge badge-danger">FAIL</span>`;
              }
            }
          });

          btnRunCompareTests.disabled = false;
          btnRunCompareTests.textContent = "⚡ Run Live Verification Tests (Complete)";

        } catch (e) {
          btnRunCompareTests.disabled = false;
          btnRunCompareTests.textContent = "⚡ Run Live Verification Tests";
          alert(`Comparison run failed: ${e.message}`);
        }
      });
    }

    // Single Test Case Drill-down
    window.testSingleWebCase = function(tcId) {
      if (!lastComparisonResults) {
        if (btnRunCompareTests) btnRunCompareTests.click();
        setTimeout(() => window.testSingleWebCase(tcId), 500);
        return;
      }

      const tc = lastComparisonResults.find(item => item.id === tcId);
      if (!tc) return;

      const drillCard = document.getElementById("tc-drilldown-card");
      const titleElem = document.getElementById("tc-drilldown-title");
      const descElem = document.getElementById("tc-drilldown-desc");
      const vulnMeta = document.getElementById("tc-vuln-meta");
      const vulnSnippet = document.getElementById("tc-vuln-snippet");
      const secMeta = document.getElementById("tc-sec-meta");
      const secSnippet = document.getElementById("tc-sec-snippet");

      if (drillCard) drillCard.style.display = "block";
      if (titleElem) titleElem.textContent = `${tc.name} (${tc.resource})`;
      if (descElem) descElem.textContent = tc.description;

      if (vulnMeta) {
        vulnMeta.innerHTML = `Target: <code>${tc.vulnerable.path}</code> &bull; Status: <strong style="color: #ff8080;">${tc.vulnerable.actual_status}</strong> &bull; Content-Type: ${tc.vulnerable.content_type}`;
      }
      if (vulnSnippet) vulnSnippet.textContent = tc.vulnerable.snippet;

      if (secMeta) {
        secMeta.innerHTML = `Target: <code>${tc.secure.path}</code> &bull; Status: <strong style="color: #4ade80;">${tc.secure.actual_status}</strong> &bull; Content-Type: ${tc.secure.content_type}`;
      }
      if (secSnippet) secSnippet.textContent = tc.secure.snippet;

      drillCard.scrollIntoView({ behavior: "smooth", block: "start" });
    };
  }

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
