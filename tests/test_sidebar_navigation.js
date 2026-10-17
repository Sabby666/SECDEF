const { chromium } = require("playwright");

(async () => {
  console.log("=== Testing SECDEF Sidebar Navigation ===");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  const testRoutes = [
    { name: "Overview", href: "/", selector: 'nav a[href="/"]' },
    { name: "Domains & Scans", href: "/domains", selector: 'nav a[href="/domains"]' },
    { name: "Asset Inventory", href: "/assets", selector: 'nav a[href="/assets"]' },
    { name: "Topology Graph", href: "/graph", selector: 'nav a[href="/graph"]' },
    { name: "Discovery Runs", href: "/discovery", selector: 'nav a[href="/discovery"]' },
    { name: "Discovery Candidates", href: "/discovery/candidates", selector: 'nav a[href="/discovery/candidates"]' },
    { name: "Security Findings", href: "/findings", selector: 'nav a[href="/findings"]' },
    { name: "Exposure Engine", href: "/exposures", selector: 'nav a[href="/exposures"]' },
    { name: "Perimeter Changes", href: "/changes", selector: 'nav a[href="/changes"]' },
    { name: "Risk Analysis", href: "/risk", selector: 'nav a[href="/risk"]' },
    { name: "Threat Feeds", href: "/intelligence", selector: 'nav a[href="/intelligence"]' },
    { name: "Cert Correlations", href: "/correlations", selector: 'nav a[href="/correlations"]' },
    { name: "AI Security Assistant", href: "/assistant", selector: 'nav a[href="/assistant"]' },
    { name: "Remediation Actions", href: "/actions", selector: 'nav a[href="/actions"]' },
    { name: "Automation Policies", href: "/automation", selector: 'nav a[href="/automation"]' },
    { name: "Continuous Verification", href: "/verification", selector: 'nav a[href="/verification"]' },
    { name: "Notifications & Alerts", href: "/notifications", selector: 'nav a[href="/notifications"]' },
    { name: "Audit Logs & Context", href: "/context", selector: 'nav a[href="/context"]' },
    { name: "Settings & Access Control", href: "/settings", selector: 'nav a[href="/settings"]' },
  ];

  let passed = 0;
  let failed = 0;

  const baseUrl = process.env.APP_URL || "http://localhost:3000";

  try {
    // 1. Initial Load to Overview
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    const initialOverviewActive = await page.$eval('nav a[href="/"]', el => el.getAttribute("aria-current"));
    if (initialOverviewActive === "page") {
      console.log("✓ Initial load: / (Overview) is active with aria-current='page'");
      passed++;
    } else {
      console.error("✗ Initial load: / (Overview) is NOT active, aria-current:", initialOverviewActive);
      failed++;
    }

    // 2. Click each nav item in succession and verify navigation and active state
    for (const item of testRoutes) {
      if (item.href === "/") continue; // Already verified initial
      
      console.log(`\nTesting click navigation to: ${item.name} (${item.href})`);
      const link = await page.$(item.selector);
      if (!link) {
        console.error(`✗ Link element not found for ${item.name} (${item.selector})`);
        failed++;
        continue;
      }

      await link.click();
      await page.waitForURL(`**${item.href}`);

      // Verify current URL
      const currentUrl = new URL(page.url()).pathname;
      if (currentUrl === item.href) {
        console.log(`  ✓ URL navigated to ${currentUrl}`);
        passed++;
      } else {
        console.error(`  ✗ Expected URL ${item.href}, got ${currentUrl}`);
        failed++;
      }

      // Verify aria-current is "page" on the clicked item
      const ariaCurrent = await page.$eval(item.selector, el => el.getAttribute("aria-current"));
      if (ariaCurrent === "page") {
        console.log(`  ✓ ${item.name} has aria-current='page'`);
        passed++;
      } else {
        console.error(`  ✗ ${item.name} does NOT have aria-current='page', got: ${ariaCurrent}`);
        failed++;
      }

      // Verify that other items are NOT marked aria-current='page'
      // Especially test disambiguation between /discovery and /discovery/candidates
      if (item.href === "/discovery/candidates") {
        const discoveryActive = await page.$eval('nav a[href="/discovery"]', el => el.getAttribute("aria-current"));
        if (!discoveryActive) {
          console.log("  ✓ Disambiguation verified: /discovery is NOT active while on /discovery/candidates");
          passed++;
        } else {
          console.error("  ✗ Disambiguation failed: /discovery is active while on /discovery/candidates!");
          failed++;
        }
      }

      // Verify Overview is not active
      const overviewActive = await page.$eval('nav a[href="/"]', el => el.getAttribute("aria-current"));
      if (!overviewActive) {
        passed++;
      } else {
        console.error("  ✗ Overview is still active while on " + item.href);
        failed++;
      }
    }

    // 3. Test nested dynamic route active state
    console.log("\nTesting nested dynamic route active state (/assets/test-asset-123)...");
    await page.goto(`${baseUrl}/assets/test-asset-123`, { waitUntil: "domcontentloaded" });
    const assetNavActive = await page.$eval('nav a[href="/assets"]', el => el.getAttribute("aria-current"));
    if (assetNavActive === "page") {
      console.log("✓ Parent route /assets is correctly active for nested route /assets/test-asset-123");
      passed++;
    } else {
      console.error("✗ Parent route /assets is NOT active for nested route /assets/test-asset-123, got:", assetNavActive);
      failed++;
    }

    console.log(`\n========================================`);
    console.log(`Total Checks: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
    console.log(`========================================`);

    if (failed > 0) {
      process.exit(1);
    }
  } catch (err) {
    console.error("Test execution error:", err);
    process.exit(1);
  } finally {
    await browser.close();
  }
})();
