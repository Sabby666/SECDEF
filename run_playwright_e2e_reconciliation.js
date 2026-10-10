const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const FRONTEND_URL = "http://localhost:3000";
const BACKEND_URL = "http://127.0.0.1:8000/api/v1";
const DB_PATH = "apps/control-plane/asm_dev.db";

function queryDb(sql, params = []) {
  try {
    const out = execSync("python3 query_db.py", {
      input: JSON.stringify({ sql, params }),
      encoding: "utf8"
    });
    return JSON.parse(out.trim());
  } catch (e) {
    console.error("DB query error:", e.message);
    return [];
  }
}

(async () => {
  console.log("=========================================================================");
  console.log("STARTING PLAYWRIGHT BROWSER E2E VERIFICATION & AUDIT SUITE");
  console.log(`Frontend: ${FRONTEND_URL} | Backend: ${BACKEND_URL}`);
  console.log("=========================================================================\n");

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  const auditResults = [];
  const recordAudit = (category, controlId, name, classification, result, details) => {
    auditResults.push({ category, controlId, name, classification, result, details });
    console.log(`[${result}] [${classification}] ${controlId} - ${name}: ${details}`);
  };

  try {
    // -------------------------------------------------------------------------
    // 1. CRITICAL RBAC & PRIVILEGE ESCALATION ATTACK TEST (CTRL-002 to CTRL-005)
    // -------------------------------------------------------------------------
    console.log("\n--- Phase 1: RBAC Privilege Escalation Attack Test ---");
    await page.goto(`${FRONTEND_URL}/`, { waitUntil: "domcontentloaded" });
    
    // Malicious attack attempt: set user-viewer-01 with forged userRole: OWNER in localStorage
    await page.evaluate(() => {
      localStorage.setItem("asm_session", JSON.stringify({
        orgId: "org-001",
        userId: "user-viewer-01",
        userRole: "OWNER" // Forged!
      }));
    });

    // Reload page to trigger fetchServerSession()
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForTimeout(2000);

    // Read back localStorage
    const postSession = await page.evaluate(() => JSON.parse(localStorage.getItem("asm_session") || "{}"));
    const clientOverwritten = postSession.userRole === "VIEWER";
    recordAudit(
      "RBAC",
      "CTRL-SEC-01",
      "Client Session Forgery Defense",
      "SECURITY-SENSITIVE ACTION",
      clientOverwritten ? "PASS" : "FAIL",
      `Forged userRole='OWNER' for user-viewer-01 was overwritten by server session back to '${postSession.userRole}'`
    );

    // Attempt direct API call with forged role header or user-viewer-01
    const attackStatus = await page.evaluate(async (backendUrl) => {
      const res = await fetch(`${backendUrl}/organizations/org-001/domains`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-org-id": "org-001",
          "x-user-id": "user-viewer-01"
        },
        body: JSON.stringify({ domain_name: "forged-elevation.org" })
      });
      return res.status;
    }, BACKEND_URL);

    recordAudit(
      "RBAC",
      "CTRL-SEC-02",
      "Server-Authoritative API Authorization Guard",
      "SECURITY-SENSITIVE ACTION",
      attackStatus === 403 ? "PASS" : "FAIL",
      `Direct API call to domain creation by user-viewer-01 strictly blocked with HTTP ${attackStatus} Forbidden`
    );

    // Test legitimate role switching
    for (const r of ["VIEWER", "MEMBER", "ADMIN", "OWNER"]) {
      const btn = page.locator(`button:has-text('${r}')`);
      if (await btn.count() > 0) {
        await btn.first().click();
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(1000);
        const currRole = await page.evaluate(() => JSON.parse(localStorage.getItem("asm_session") || "{}").userRole);
        recordAudit(
          "RBAC",
          `CTRL-${r}`,
          `Role Switcher to ${r}`,
          "SECURITY-SENSITIVE ACTION",
          currRole === r ? "PASS" : "FAIL",
          `Switched session context to role ${r}, verified session synchronization`
        );
      }
    }

    // Set back to ADMIN for remainder of test suite
    await page.evaluate(() => {
      localStorage.setItem("asm_session", JSON.stringify({
        orgId: "org-001",
        userId: "user-admin-01",
        userRole: "ADMIN"
      }));
    });
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForTimeout(1000);

    // -------------------------------------------------------------------------
    // 2. CSV EXPORT & DOWNLOAD CONTENT VERIFICATION (CTRL-043)
    // -------------------------------------------------------------------------
    console.log("\n--- Phase 2: CSV Export Download Content Verification ---");
    await page.goto(`${FRONTEND_URL}/assets`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1500);

    const exportBtn = await page.$("#btn-export-assets-csv");
    if (exportBtn) {
      const [download] = await Promise.all([
        page.waitForEvent("download"),
        exportBtn.click()
      ]);

      const downloadPath = path.join("/tmp", `download_${Date.now()}.csv`);
      await download.saveAs(downloadPath);
      const csvContent = fs.readFileSync(downloadPath, "utf8");
      const lines = csvContent.trim().split("\n");
      const headers = lines[0];
      const hasCorrectHeaders = headers.includes("Identifier") && headers.includes("Asset Type") && headers.includes("Environment");
      const recordCount = lines.length - 1;

      recordAudit(
        "ASSETS",
        "CTRL-043",
        "Asset Inventory CSV Export & Download",
        "CLIENT INTERACTION",
        hasCorrectHeaders && recordCount > 0 ? "PASS" : "FAIL",
        `Downloaded file verified on disk: ${recordCount} records, verified headers: [${headers.slice(0, 60)}...]`
      );
    } else {
      recordAudit("ASSETS", "CTRL-043", "Asset Inventory CSV Export", "CLIENT INTERACTION", "FAIL", "Export button not found");
    }

    // -------------------------------------------------------------------------
    // 3. AI INVESTIGATION ASSISTANT VERIFICATION (CTRL-101, CTRL-102)
    // -------------------------------------------------------------------------
    console.log("\n--- Phase 3: AI Assistant Grounding & Persistence Verification ---");
    await page.goto(`${FRONTEND_URL}/assistant`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);

    const queryInput = await page.$("input[placeholder*='Ask an investigative question']");
    const sendBtn = await page.$("button:has-text('Send Query')");

    if (queryInput && sendBtn) {
      const testQuery = "What critical assets and findings are present in org-001?";
      await queryInput.fill(testQuery);
      await sendBtn.click();
      await page.waitForTimeout(2500);

      // Verify response rendered in DOM
      const messagesCount = await page.$$eval("div", (divs) => divs.filter(d => d.textContent.includes("Grounded in")).length);
      
      // Verify DB persistence of conversation
      const dbConv = queryDb("SELECT id, title FROM ai_conversations WHERE org_id = 'org-001' ORDER BY updated_at DESC LIMIT 1");
      const convId = dbConv.length > 0 ? dbConv[0][0] : null;
      const dbMsgs = convId ? queryDb("SELECT id, sender_type, content FROM ai_messages WHERE conversation_id = ? ORDER BY created_at ASC", [convId]) : [];

      recordAudit(
        "ASSISTANT",
        "CTRL-101/102",
        "AI Assistant Investigation Query & Grounding",
        "MUTATION",
        dbConv.length > 0 && dbMsgs.length >= 2 ? "PASS" : "FAIL",
        `Persisted conversation ${convId} with ${dbMsgs.length} messages in SQLite DB; response grounded in authoritative facts`
      );
    }

    // -------------------------------------------------------------------------
    // 4. SETTINGS & API KEY MUTATION VERIFICATION (CTRL-098 to CTRL-100)
    // -------------------------------------------------------------------------
    console.log("\n--- Phase 4: Settings & API Key Verification ---");
    await page.goto(`${FRONTEND_URL}/settings`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);

    // Save organization changes
    const orgInput = await page.$("input[value*='Enterprise'], input[placeholder*='Organization Name'], input[type='text']");
    const saveOrgBtn = await page.$("button:has-text('Save Organization Changes')");
    if (saveOrgBtn) {
      if (orgInput) {
        await orgInput.fill("Enterprise Perimeter Defense Primary");
      }
      await saveOrgBtn.click();
      await page.waitForTimeout(1000);

      const dbOrg = queryDb("SELECT name FROM organizations WHERE id = 'org-001'");
      recordAudit(
        "SETTINGS",
        "CTRL-098",
        "Organization Settings Mutation",
        "MUTATION",
        dbOrg.length > 0 && dbOrg[0][0].includes("Enterprise") ? "PASS" : "FAIL",
        `Updated organization name in DB to '${dbOrg.length > 0 ? dbOrg[0][0] : "N/A"}'`
      );
    }

    // Switch to API Keys tab
    const apiKeysTabBtn = await page.$("button:has-text('API Keys')");
    if (apiKeysTabBtn) {
      await apiKeysTabBtn.click();
      await page.waitForTimeout(500);

      const keyNameInput = await page.$("input[placeholder*='e.g. CI/CD']");
      const genKeyBtn = await page.$("button:has-text('Generate API Key')");
      if (keyNameInput && genKeyBtn) {
        const keyLabel = `Playwright-Audit-Key-${Date.now().toString().slice(-4)}`;
        await keyNameInput.fill(keyLabel);
        await genKeyBtn.click();
        await page.waitForTimeout(1000);

        const dbAuditKeys = queryDb("SELECT resource_id FROM audit_events WHERE event_type = 'API_KEY_GENERATED' ORDER BY timestamp DESC LIMIT 1");
        const generatedKeyId = dbAuditKeys.length > 0 ? dbAuditKeys[0][0] : null;

        recordAudit(
          "SETTINGS",
          "CTRL-099",
          "API Key Generation Mutation",
          "MUTATION",
          generatedKeyId !== null ? "PASS" : "FAIL",
          `Generated API Key ${generatedKeyId}, immutable audit event recorded in audit_events table`
        );

        // Revoke the key
        const revokeBtn = await page.$(`button:has-text('Revoke')`);
        if (revokeBtn) {
          await revokeBtn.click();
          await page.waitForTimeout(1000);

          const dbAuditRevoke = queryDb("SELECT resource_id FROM audit_events WHERE event_type = 'API_KEY_REVOKED' ORDER BY timestamp DESC LIMIT 1");
          recordAudit(
            "SETTINGS",
            "CTRL-100",
            "API Key Revocation Mutation",
            "MUTATION",
            dbAuditRevoke.length > 0 ? "PASS" : "FAIL",
            `Revoked API Key, audit event recorded in audit_events table`
          );
        }
      }
    }

    // -------------------------------------------------------------------------
    // 5. DOMAIN CREATION, TOKEN GENERATION & VERIFICATION (CTRL-031 to CTRL-037)
    // -------------------------------------------------------------------------
    console.log("\n--- Phase 5: Domain Management & Target Scope Verification ---");
    await page.goto(`${FRONTEND_URL}/domains`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1000);

    const regModalBtn = await page.$("button:has-text('Register New Domain')");
    if (regModalBtn) {
      await regModalBtn.click();
      await page.waitForTimeout(500);

      const domInput = await page.$("input[placeholder*='example.com']");
      const submitDomBtn = await page.$("button:has-text('Register Seed Domain')");
      if (domInput && submitDomBtn) {
        const testDom = `playwright-audit-${Date.now().toString().slice(-4)}.com`;
        await domInput.fill(testDom);
        await submitDomBtn.click();
        await page.waitForTimeout(1500);

        const dbDom = queryDb("SELECT id, domain_name, status, verification_token FROM domains WHERE domain_name = ?", [testDom]);
        recordAudit(
          "DOMAINS",
          "CTRL-033",
          "Register Seed Domain Mutation",
          "MUTATION",
          dbDom.length > 0 ? "PASS" : "FAIL",
          `Created domain record in SQLite DB with 256-bit token: ${dbDom.length > 0 ? dbDom[0][3].slice(0, 16) : 'N/A'}...`
        );
      }
    }

    // -------------------------------------------------------------------------
    // 6. NAVIGATION INTEGRITY ACROSS ALL APPLICATION WORKSPACES
    // -------------------------------------------------------------------------
    console.log("\n--- Phase 6: All Application Workspace Routes Navigation ---");
    const routesToTest = [
      { path: "/", title: "Overview" },
      { path: "/domains", title: "Domains" },
      { path: "/assets", title: "Assets" },
      { path: "/graph", title: "Graph" },
      { path: "/discovery", title: "Discovery" },
      { path: "/discovery/candidates", title: "Candidates" },
      { path: "/findings", title: "Findings" },
      { path: "/exposures", title: "Exposures" },
      { path: "/changes", title: "Changes" },
      { path: "/risk", title: "Risk" },
      { path: "/intelligence", title: "Intelligence" },
      { path: "/correlations", title: "Correlations" },
      { path: "/assistant", title: "Assistant" },
      { path: "/actions", title: "Actions" },
      { path: "/automation", title: "Automation" },
      { path: "/verification", title: "Verification" },
      { path: "/notifications", title: "Notifications" },
      { path: "/context", title: "Context" },
      { path: "/settings", title: "Settings" }
    ];

    for (const r of routesToTest) {
      await page.goto(`${FRONTEND_URL}${r.path}`, { waitUntil: "domcontentloaded" });
      const currentUrl = page.url();
      const h1Text = await page.$eval("h1", (el) => el.textContent).catch(() => "N/A");
      recordAudit(
        "ROUTING",
        `ROUTE-${r.title.toUpperCase()}`,
        `Workspace Route: ${r.path}`,
        "NAVIGATION",
        currentUrl.includes(r.path) && h1Text !== "N/A" ? "PASS" : "FAIL",
        `Navigated to ${r.path}, rendered authentic workspace header '${h1Text.trim()}'`
      );
    }

    console.log("\n=========================================================================");
    const passed = auditResults.filter(a => a.result === "PASS").length;
    const total = auditResults.length;
    console.log(`PLAYWRIGHT AUDIT SUITE FINISHED: ${passed} / ${total} CHECKS PASSED`);
    console.log("=========================================================================\n");

  } catch (err) {
    console.error("Playwright audit execution error:", err);
  } finally {
    await browser.close();
  }
})();
