/**
 * SecureLab — SQL Injection Explorer
 * Frontend Controller & Guided Tour Engine
 * Plain JavaScript (Vanilla, no framework dependencies)
 */

(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------
  const state = {
    currentTab: "overview",
    activeMode: "vulnerable", // "vulnerable" | "secure"
    labView: "both",          // "both" | "vulnerable" | "secure"
    tourActive: false,
    tourStep: 1,
    totalSteps: 6
  };

  // ---------------------------------------------------------------------------
  // DOM Elements
  // ---------------------------------------------------------------------------
  const navTabs = document.querySelectorAll(".nav-tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  const pillVulnerable = document.getElementById("pill-vulnerable");
  const pillSecure = document.getElementById("pill-secure");

  const labViewBtns = document.querySelectorAll(".lab-view-btn");
  const colVulnerable = document.getElementById("col-vulnerable");
  const colSecure = document.getElementById("col-secure");
  const labComparisonGrid = document.getElementById("lab-comparison-grid");

  // Forms & Inputs
  const vulnUsernameInput = document.getElementById("vuln-username");
  const vulnPasswordInput = document.getElementById("vuln-password");
  const btnRunVulnerable = document.getElementById("btn-run-vulnerable");
  const resultVulnerable = document.getElementById("result-vulnerable");

  const secUsernameInput = document.getElementById("sec-username");
  const secPasswordInput = document.getElementById("sec-password");
  const btnRunSecure = document.getElementById("btn-run-secure");
  const resultSecure = document.getElementById("result-secure");

  // SQL Inspector
  const inspectorVulnQuery = document.getElementById("inspector-vuln-query");
  const inspectorVulnTokens = document.getElementById("inspector-vuln-tokens");
  const inspectorSecQuery = document.getElementById("inspector-sec-query");
  const inspectorSecParams = document.getElementById("inspector-sec-params");
  const inspectorExplanation = document.getElementById("inspector-explanation");

  // Guided Tour Elements
  const demoBackdrop = document.getElementById("demo-backdrop");
  const guidedDemoCard = document.getElementById("guided-demo-card");
  const tourStepCounter = document.getElementById("tour-step-counter");
  const tourStepTitle = document.getElementById("tour-step-title");
  const tourStepBody = document.getElementById("tour-step-body");
  const tourBtnBack = document.getElementById("tour-btn-back");
  const tourBtnNext = document.getElementById("tour-btn-next");
  const tourBtnExit = document.getElementById("tour-btn-exit");

  // ---------------------------------------------------------------------------
  // Navigation & Tab Switching
  // ---------------------------------------------------------------------------
  function switchTab(tabId) {
    state.currentTab = tabId;

    navTabs.forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tabId);
    });

    tabPanes.forEach((pane) => {
      pane.classList.toggle("active", pane.id === `pane-${tabId}`);
    });

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  navTabs.forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  document.getElementById("btn-goto-lab")?.addEventListener("click", () => switchTab("lab"));
  document.getElementById("banner-remediation-btn")?.addEventListener("click", () => switchTab("explanation"));

  // ---------------------------------------------------------------------------
  // Mode & Lab View Toggles
  // ---------------------------------------------------------------------------
  function setMode(mode) {
    state.activeMode = mode;
    if (mode === "vulnerable") {
      pillVulnerable.className = "mode-pill-btn active-vulnerable";
      pillSecure.className = "mode-pill-btn";
    } else {
      pillVulnerable.className = "mode-pill-btn";
      pillSecure.className = "mode-pill-btn active-secure";
    }
  }

  pillVulnerable.addEventListener("click", () => {
    setMode("vulnerable");
    if (state.currentTab !== "lab") switchTab("lab");
  });

  pillSecure.addEventListener("click", () => {
    setMode("secure");
    if (state.currentTab !== "lab") switchTab("lab");
  });

  function setLabView(view) {
    state.labView = view;
    labViewBtns.forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === view);
    });

    if (view === "both") {
      colVulnerable.style.display = "flex";
      colSecure.style.display = "flex";
      labComparisonGrid.style.gridTemplateColumns = "1fr 1fr";
    } else if (view === "vulnerable") {
      colVulnerable.style.display = "flex";
      colSecure.style.display = "none";
      labComparisonGrid.style.gridTemplateColumns = "1fr";
      setMode("vulnerable");
    } else if (view === "secure") {
      colVulnerable.style.display = "none";
      colSecure.style.display = "flex";
      labComparisonGrid.style.gridTemplateColumns = "1fr";
      setMode("secure");
    }
  }

  labViewBtns.forEach((btn) => {
    btn.addEventListener("click", () => setLabView(btn.dataset.view));
  });

  // ---------------------------------------------------------------------------
  // Payload Helper Pills
  // ---------------------------------------------------------------------------
  document.querySelectorAll(".payload-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      const target = pill.dataset.target;
      const username = pill.dataset.u || "";
      const password = pill.dataset.p || "";

      if (target === "vuln") {
        vulnUsernameInput.value = username;
        vulnPasswordInput.value = password;
        vulnUsernameInput.focus();
      } else if (target === "sec") {
        secUsernameInput.value = username;
        secPasswordInput.value = password;
        secUsernameInput.focus();
      }
    });
  });

  // ---------------------------------------------------------------------------
  // API Calls: Vulnerable & Secure Queries
  // ---------------------------------------------------------------------------
  async function executeVulnerableLogin() {
    const username = vulnUsernameInput.value;
    const password = vulnPasswordInput.value;

    btnRunVulnerable.disabled = true;
    btnRunVulnerable.textContent = "Executing Query...";

    try {
      const response = await fetch("/api/vulnerable/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();
      renderVulnerableResult(data);
      updateInspectorForVulnerable(data, username);
    } catch (err) {
      resultVulnerable.innerHTML = `
        <div class="result-outcome-header" style="color: var(--status-danger);">
          <span>❌</span> Network / Server Error
        </div>
        <p style="color: var(--text-secondary);">${err.message}</p>
      `;
    } finally {
      btnRunVulnerable.disabled = false;
      btnRunVulnerable.textContent = "Run Vulnerable Query";
    }
  }

  async function executeSecureLogin() {
    const username = secUsernameInput.value;
    const password = secPasswordInput.value;

    btnRunSecure.disabled = true;
    btnRunSecure.textContent = "Executing Query...";

    try {
      const response = await fetch("/api/secure/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();
      renderSecureResult(data);
      updateInspectorForSecure(data, username);
    } catch (err) {
      resultSecure.innerHTML = `
        <div class="result-outcome-header" style="color: var(--status-danger);">
          <span>❌</span> Network / Server Error
        </div>
        <p style="color: var(--text-secondary);">${err.message}</p>
      `;
    } finally {
      btnRunSecure.disabled = false;
      btnRunSecure.textContent = "Run Secure Query";
    }
  }

  btnRunVulnerable.addEventListener("click", executeVulnerableLogin);
  btnRunSecure.addEventListener("click", executeSecureLogin);

  vulnUsernameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") executeVulnerableLogin();
  });
  vulnPasswordInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") executeVulnerableLogin();
  });

  secUsernameInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") executeSecureLogin();
  });
  secPasswordInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") executeSecureLogin();
  });

  // ---------------------------------------------------------------------------
  // Result Renderers
  // ---------------------------------------------------------------------------
  function renderVulnerableResult(data) {
    if (data.database_error) {
      resultVulnerable.innerHTML = `
        <div class="result-outcome-header outcome-bypassed">
          <span>⚠️</span> ${data.message}
        </div>
        <p style="color: #611a15; font-size: 12px; margin-bottom: 8px;">
          ${data.explanation}
        </p>
        <div style="background: #fff; padding: 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 11px; color: #a12b2b;">
          Database Error: ${data.database_error}
        </div>
      `;
      return;
    }

    if (data.success && data.is_bypass) {
      const u = data.authenticated_user;
      resultVulnerable.innerHTML = `
        <div class="result-outcome-header outcome-bypassed">
          <span>🔓</span> AUTHENTICATION BYPASS SUCCESSFUL
        </div>
        <p style="color: #611a15; font-size: 12.5px; line-height: 1.5; margin-bottom: 8px;">
          <strong>Vulnerability Triggered:</strong> Untrusted input altered the SQL grammar. The query's WHERE clause evaluated to TRUE without matching the password!
        </p>
        <div class="user-identity-card" style="border-left: 3px solid var(--status-danger);">
          <div class="user-identity-row">
            <span>Authenticated User:</span>
            <strong>${u.full_name} (${u.username})</strong>
          </div>
          <div class="user-identity-row">
            <span>Authorized Role:</span>
            <span class="role-badge role-admin">${u.role}</span>
          </div>
          <div class="user-identity-row">
            <span>Email:</span>
            <code>${u.email}</code>
          </div>
        </div>
      `;
    } else if (data.success) {
      const u = data.authenticated_user;
      resultVulnerable.innerHTML = `
        <div class="result-outcome-header" style="color: var(--status-success);">
          <span>✅</span> Login Successful (Standard Credentials)
        </div>
        <p style="color: var(--text-secondary); font-size: 12px; margin-bottom: 8px;">
          Valid user record matched.
        </p>
        <div class="user-identity-card">
          <div class="user-identity-row">
            <span>User:</span>
            <strong>${u.full_name} (${u.username})</strong>
          </div>
          <div class="user-identity-row">
            <span>Role:</span>
            <span class="role-badge role-student">${u.role}</span>
          </div>
        </div>
      `;
    } else {
      resultVulnerable.innerHTML = `
        <div class="result-outcome-header" style="color: #666;">
          <span>❌</span> ${data.message}
        </div>
        <p style="color: var(--text-secondary); font-size: 12px;">
          ${data.explanation}
        </p>
      `;
    }
  }

  function renderSecureResult(data) {
    if (data.success) {
      const u = data.authenticated_user;
      resultSecure.innerHTML = `
        <div class="result-outcome-header" style="color: var(--status-success);">
          <span>✅</span> ${data.message}
        </div>
        <p style="color: var(--text-secondary); font-size: 12px; margin-bottom: 8px;">
          ${data.explanation}
        </p>
        <div class="user-identity-card" style="border-left: 3px solid var(--status-success);">
          <div class="user-identity-row">
            <span>User:</span>
            <strong>${u.full_name} (${u.username})</strong>
          </div>
          <div class="user-identity-row">
            <span>Role:</span>
            <span class="role-badge role-student">${u.role}</span>
          </div>
        </div>
      `;
    } else {
      resultSecure.innerHTML = `
        <div class="result-outcome-header outcome-rejected">
          <span>🛡️</span> Authentication Safely Rejected
        </div>
        <p style="color: #1b5336; font-size: 12.5px; line-height: 1.5; margin-bottom: 8px;">
          ${data.explanation}
        </p>
        <div class="user-identity-card" style="border-left: 3px solid var(--status-success);">
          <div class="user-identity-row">
            <span>Security Outcome:</span>
            <strong style="color: var(--status-success);">Attack Neutralized</strong>
          </div>
          <div class="user-identity-row">
            <span>Database Behavior:</span>
            <span>Input treated strictly as string value</span>
          </div>
        </div>
      `;
    }
  }

  // ---------------------------------------------------------------------------
  // SQL Inspector Updates
  // ---------------------------------------------------------------------------
  function updateInspectorForVulnerable(data, rawUsername) {
    const rawQuery = data.constructed_query || `SELECT * FROM users WHERE username = '${rawUsername}' AND password = ''`;

    // Highlight injected tokens if present
    let formatted = escapeHtml(rawQuery);
    if (rawUsername.includes("'") || rawUsername.includes("--") || rawUsername.toUpperCase().includes("OR")) {
      const safeToken = escapeHtml(rawUsername);
      formatted = formatted.replace(
        safeToken,
        `<span class="query-token-injected">${safeToken}</span>`
      );
    }

    inspectorVulnQuery.innerHTML = formatted;

    if (data.is_bypass) {
      inspectorVulnTokens.innerHTML = `
        <strong style="color: var(--status-danger);">⚠️ Grammar Tampering Detected:</strong>
        The injected input <code>${escapeHtml(rawUsername)}</code> escaped the string literal boundary. The SQLite parser evaluated <code>OR 1=1</code> as TRUE and treated <code>--</code> as a comment marker, removing the password requirement.
      `;
      inspectorExplanation.innerHTML = `
        <strong>SQL Analysis:</strong> Because the query was constructed using direct string concatenation, the database could not distinguish between code syntax and user input. The input altered the structure of the SQL query.
      `;
    } else if (data.database_error) {
      inspectorVulnTokens.innerHTML = `
        <strong style="color: var(--status-danger);">Syntax Error:</strong> The unescaped quotation mark broke the SQL syntax tree before execution.
      `;
    } else {
      inspectorVulnTokens.innerHTML = `
        <strong>Evaluation:</strong> Standard string concatenation. No injection syntax detected.
      `;
    }
  }

  function updateInspectorForSecure(data, rawUsername) {
    const template = data.query_template || "SELECT id, username, full_name, role, email FROM users WHERE username = ? AND password = ?";
    
    // Highlight parameter placeholders
    const formatted = escapeHtml(template).replaceAll(
      "?",
      `<span class="query-token-param">?</span>`
    );
    inspectorSecQuery.innerHTML = formatted;

    const boundParams = data.bound_parameters || [rawUsername, "••••••••"];
    inspectorSecParams.innerHTML = `
      <strong>Bound Parameters:</strong> [1: "${escapeHtml(boundParams[0])}", 2: "${escapeHtml(boundParams[1])}"]
    `;

    inspectorExplanation.innerHTML = `
      <strong>Key Insight:</strong> Notice the <code>?</code> placeholders. The database compiles the SQL command structure <em>before</em> binding parameter values. Any quotes, <code>OR</code> keywords, or <code>--</code> comment markers in parameter 1 are treated strictly as harmless characters inside the string value.
    `;
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

  // ---------------------------------------------------------------------------
  // Reset Demo Functionality
  // ---------------------------------------------------------------------------
  async function resetDemo() {
    try {
      await fetch("/api/reset", { method: "POST" });
    } catch (e) {
      console.warn("Reset API error:", e);
    }

    vulnUsernameInput.value = "";
    vulnPasswordInput.value = "";
    secUsernameInput.value = "";
    secPasswordInput.value = "";

    resultVulnerable.innerHTML = `
      <div class="result-placeholder">
        Awaiting query execution. Enter credentials or select a test input above.
      </div>
    `;

    resultSecure.innerHTML = `
      <div class="result-placeholder">
        Awaiting query execution. Enter credentials or select a test input above.
      </div>
    `;

    inspectorVulnQuery.textContent = `SELECT id, username, full_name, role, email\nFROM users\nWHERE username = '' AND password = ''`;
    inspectorVulnTokens.innerHTML = `<strong>Evaluation:</strong> Waiting for execution...`;

    inspectorSecQuery.textContent = `SELECT id, username, full_name, role, email\nFROM users\nWHERE username = ? AND password = ?`;
    inspectorSecParams.innerHTML = `<strong>Bound Parameters:</strong> (username = '', password = '')`;

    inspectorExplanation.innerHTML = `
      <strong>Key Insight:</strong> In the vulnerable implementation, the database compiler treats whatever string you type as direct SQL instructions. In the secure implementation, the database first compiles the query template, and then treats your input strictly as literal string values.
    `;

    setMode("vulnerable");
    setLabView("both");
    exitTour();
    switchTab("overview");
  }

  document.getElementById("banner-reset-demo-btn")?.addEventListener("click", resetDemo);

  // ---------------------------------------------------------------------------
  // Guided Demo Tour (6 Steps)
  // ---------------------------------------------------------------------------
  const tourSteps = [
    {
      step: 1,
      title: "Welcome to the SQL Injection Explorer",
      body: `
        <p>This laboratory demonstrates how untrusted user input can break out of its intended data context and execute as SQL commands.</p>
        <p>The database has three test accounts: <code>admin</code>, <code>john_doe</code>, and <code>sarah_connor</code>.</p>
      `,
      hint: `Click <strong>Next</strong> to open the lab and test legitimate credentials.`,
      tab: "overview",
      highlightSelector: ".scenario-card-featured",
      onEnter: () => {
        switchTab("overview");
      }
    },
    {
      step: 2,
      title: "Step 1: Test Normal Student Credentials",
      body: `
        <p>First, observe how legitimate authentication works under intended usage.</p>
        <p>We've loaded valid credentials for student <strong>john_doe</strong> (password: <code>StudentPass123</code>).</p>
      `,
      hint: `Click <strong>Run Vulnerable Query</strong> in the left column (or click <strong>Next</strong> to auto-run).`,
      tab: "lab",
      highlightSelector: "#col-vulnerable",
      onEnter: () => {
        switchTab("lab");
        setLabView("both");
        setMode("vulnerable");
        vulnUsernameInput.value = "john_doe";
        vulnPasswordInput.value = "StudentPass123";
      },
      autoAction: () => {
        executeVulnerableLogin();
      }
    },
    {
      step: 3,
      title: "Step 2: Enter the SQL Injection Payload",
      body: `
        <p>Now let's test an attack. Instead of a normal username, we enter: <br><strong style="font-family: var(--font-mono); color: var(--status-danger);">' OR 1=1 --</strong> with <em>no password</em>.</p>
        <p>Notice what each character does: <code>'</code> closes the string literal, <code>OR 1=1</code> forces a TRUE condition, and <code>--</code> comments out the password requirement.</p>
      `,
      hint: `Click <strong>Run Vulnerable Query</strong> to observe the database bypass!`,
      tab: "lab",
      highlightSelector: "#form-vulnerable",
      onEnter: () => {
        switchTab("lab");
        setLabView("both");
        setMode("vulnerable");
        vulnUsernameInput.value = "' OR 1=1 --";
        vulnPasswordInput.value = "";
      },
      autoAction: () => {
        executeVulnerableLogin();
      }
    },
    {
      step: 4,
      title: "Step 3: Inspect the Authentication Bypass",
      body: `
        <p><strong style="color: var(--status-danger);">Bypass Achieved!</strong> You are now authenticated as <strong>Dr. Alice Vance (Administrator)</strong> without knowing any password!</p>
        <p>Inspect the <strong>Live SQL Inspector</strong> below to see how string concatenation merged the payload directly into the SQL command.</p>
      `,
      hint: `Notice how the query evaluated: <code>WHERE username = '' OR 1=1</code>. Click <strong>Next</strong> to see how Secure Mode defends against this.`,
      tab: "lab",
      highlightSelector: "#panel-sql-inspector",
      onEnter: () => {
        switchTab("lab");
        if (!resultVulnerable.textContent.includes("AUTHENTICATION BYPASS")) {
          vulnUsernameInput.value = "' OR 1=1 --";
          vulnPasswordInput.value = "";
          executeVulnerableLogin();
        }
        document.getElementById("panel-sql-inspector")?.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    },
    {
      step: 5,
      title: "Step 4: Defend with Secure Mode",
      body: `
        <p>Now, let's submit the exact same injection payload <code>' OR 1=1 --</code> to the <strong>Secure Portal</strong>.</p>
        <p>The secure code uses <strong>parameterized queries</strong>: <br><code style="font-size: 12px;">SELECT * FROM users WHERE username = ? AND password = ?</code></p>
      `,
      hint: `Click <strong>Run Secure Query</strong> in the right column to test the defense.`,
      tab: "lab",
      highlightSelector: "#col-secure",
      onEnter: () => {
        switchTab("lab");
        setLabView("both");
        setMode("secure");
        secUsernameInput.value = "' OR 1=1 --";
        secPasswordInput.value = "";
      },
      autoAction: () => {
        executeSecureLogin();
      }
    },
    {
      step: 6,
      title: "Step 5: Attack Neutralized & Secure Coding Rule",
      body: `
        <p><strong style="color: var(--status-success);">Authentication Safely Rejected!</strong></p>
        <p>Because the query was parameterized, the SQLite database searched for a user whose literal username string was <code>' OR 1=1 --</code>. The quotation marks and SQL operators were never executed as code.</p>
      `,
      hint: `Click <strong>Next</strong> or <strong>Exit</strong> to review the complete Explanation & Remediation guide.`,
      tab: "explanation",
      highlightSelector: ".rule-banner",
      onEnter: () => {
        switchTab("explanation");
      }
    }
  ];

  function startTour() {
    state.tourActive = true;
    state.tourStep = 1;
    demoBackdrop.classList.add("active");
    guidedDemoCard.classList.add("active");
    renderTourStep(1);
  }

  function exitTour() {
    state.tourActive = false;
    demoBackdrop.classList.remove("active");
    guidedDemoCard.classList.remove("active");
    clearTourHighlights();
  }

  function clearTourHighlights() {
    document.querySelectorAll(".tour-highlight").forEach((el) => {
      el.classList.remove("tour-highlight");
    });
  }

  function renderTourStep(stepNum) {
    clearTourHighlights();
    const stepConfig = tourSteps[stepNum - 1];
    if (!stepConfig) return;

    tourStepCounter.textContent = `STEP ${stepConfig.step} OF ${state.totalSteps}`;
    tourStepTitle.textContent = stepConfig.title;
    tourStepBody.innerHTML = `
      ${stepConfig.body}
      <div class="tour-hint-box">${stepConfig.hint}</div>
    `;

    tourBtnBack.disabled = stepNum === 1;
    tourBtnNext.textContent = stepNum === state.totalSteps ? "Finish ➔" : "Next ➔";

    if (typeof stepConfig.onEnter === "function") {
      stepConfig.onEnter();
    }

    if (stepConfig.highlightSelector) {
      setTimeout(() => {
        const target = document.querySelector(stepConfig.highlightSelector);
        if (target) {
          target.classList.add("tour-highlight");
        }
      }, 100);
    }
  }

  tourBtnNext.addEventListener("click", () => {
    const currentStepConfig = tourSteps[state.tourStep - 1];
    if (currentStepConfig && typeof currentStepConfig.autoAction === "function") {
      currentStepConfig.autoAction();
    }

    if (state.tourStep < state.totalSteps) {
      state.tourStep++;
      renderTourStep(state.tourStep);
    } else {
      exitTour();
      switchTab("explanation");
    }
  });

  tourBtnBack.addEventListener("click", () => {
    if (state.tourStep > 1) {
      state.tourStep--;
      renderTourStep(state.tourStep);
    }
  });

  tourBtnExit.addEventListener("click", exitTour);
  demoBackdrop.addEventListener("click", exitTour);

  document.getElementById("btn-start-guided-tour")?.addEventListener("click", startTour);
  document.getElementById("banner-start-demo-btn")?.addEventListener("click", startTour);

  // ---------------------------------------------------------------------------
  // Initial Page State
  // ---------------------------------------------------------------------------
  switchTab("overview");
  setMode("vulnerable");
  setLabView("both");

})();
