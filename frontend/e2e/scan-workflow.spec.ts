import { test, expect } from "@playwright/test";

const mockUser = {
  email: "test@example.com",
  name: "Test User",
  avatar_url: null,
};

const mockScan = {
  id: "scan-123",
  source_type: "git",
  source_url: "https://github.com/example/project.git",
  status: "completed",
  created_at: "2025-01-01T12:00:00Z",
  completed_at: "2025-01-01T12:05:00Z",
  total_findings: 3,
  critical_count: 1,
  high_count: 1,
  medium_count: 1,
  low_count: 0,
  security_score: 65,
  detected_languages: ["python"],
};

const mockFindings = [
  {
    id: "finding-1",
    tool: "bandit",
    rule_id: "B301",
    file_path: "app/utils.py",
    line_start: 42,
    line_end: 42,
    code_snippet: "data = pickle.loads(payload)",
    severity: "critical",
    owasp_category: "A08",
    title: "Unsafe deserialization with pickle",
    description: "Using pickle.loads on untrusted data can lead to arbitrary code execution.",
    has_fix: false,
    fixed_code: "",
    fix_explanation: "",
    fix_pr_url: "",
    status: "open",
  },
  {
    id: "finding-2",
    tool: "semgrep",
    rule_id: "sql-injection",
    file_path: "app/db.py",
    line_start: 15,
    line_end: 15,
    code_snippet: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    severity: "high",
    owasp_category: "A05",
    title: "SQL Injection vulnerability",
    description: "User input is directly interpolated into SQL query.",
    has_fix: false,
    fixed_code: "",
    fix_explanation: "",
    fix_pr_url: "",
    status: "open",
  },
  {
    id: "finding-3",
    tool: "bandit",
    rule_id: "B501",
    file_path: "app/api.py",
    line_start: 23,
    line_end: 23,
    code_snippet: "requests.get(url, verify=False)",
    severity: "medium",
    owasp_category: "A04",
    title: "SSL verification disabled",
    description: "SSL certificate verification is disabled.",
    has_fix: false,
    fixed_code: "",
    fix_explanation: "",
    fix_pr_url: "",
    status: "open",
  },
];

test.describe("Scan workflow", () => {
  test.beforeEach(async ({ page }) => {
    // Mock auth
    await page.route("**/api/accounts/me/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockUser) }),
    );
    await page.route("**/api/accounts/github/repos/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) }),
    );
  });

  test("should submit a new scan via git URL", async ({ page }) => {
    // Mock scan creation
    await page.route("**/api/scanner/scans/", (route) => {
      if (route.request().method() === "POST") {
        return route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify({ id: "scan-123", status: "pending" }),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([mockScan]),
      });
    });
    await page.route("**/api/scanner/stats/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ total_scans: 1, completed_scans: 1, total_findings: 3, total_critical: 1, avg_score: 65 }) }),
    );
    await page.route("**/api/scanner/owasp-chart/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) }),
    );
    // Mock scan detail page
    await page.route("**/api/scanner/scans/scan-123/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockScan) }),
    );
    await page.route("**/api/scanner/scans/scan-123/findings/**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockFindings) }),
    );
    await page.route("**/api/scanner/scans/scan-123/owasp-chart/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) }),
    );

    await page.goto("/dashboard");

    // Fill in the git URL
    const urlInput = page.locator('input[type="url"]');
    await urlInput.fill("https://github.com/example/project.git");

    // Submit the form
    await page.click('button[type="submit"]');

    // Should navigate to scan detail page
    await page.waitForURL("**/scans/scan-123**", { timeout: 10_000 });
    expect(page.url()).toContain("/scans/scan-123");
  });

  test("should display scan results with findings", async ({ page }) => {
    await page.route("**/api/scanner/scans/scan-123/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockScan) }),
    );
    await page.route("**/api/scanner/scans/scan-123/findings/**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockFindings) }),
    );
    await page.route("**/api/scanner/scans/scan-123/owasp-chart/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) }),
    );

    await page.goto("/scans/scan-123");

    // Should show the project name
    await expect(page.locator("text=project")).toBeVisible({ timeout: 10_000 });

    // Should show severity counts
    await expect(page.locator("text=Critical").first()).toBeVisible();

    // Should show findings in table
    await expect(page.locator("text=Unsafe deserialization").first()).toBeVisible();
    await expect(page.locator("text=SQL Injection").first()).toBeVisible();
  });

  test("should display scan list on scans page", async ({ page }) => {
    await page.route("**/api/scanner/scans/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([mockScan]) }),
    );

    await page.goto("/scans");

    // Should show the scan
    await expect(page.locator("text=project")).toBeVisible({ timeout: 10_000 });
    await expect(page.locator("text=completed").first()).toBeVisible();
  });
});
