import { test, expect } from "@playwright/test";

const mockUser = {
  email: "test@example.com",
  name: "Test User",
  avatar_url: null,
};

test.describe("Navigation", () => {
  test.beforeEach(async ({ page }) => {
    // Mock auth for all requests
    await page.route("**/api/accounts/me/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockUser) }),
    );
    await page.route("**/api/scanner/**", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) }),
    );
    await page.route("**/api/accounts/github/repos/", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) }),
    );
  });

  test("should navigate to dashboard", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page.locator("h1")).toBeVisible({ timeout: 10_000 });
  });

  test("should navigate to projects page via sidebar", async ({ page }) => {
    await page.goto("/dashboard");

    // Click on Projects in sidebar
    await page.click('a[href="/projects"]');
    await page.waitForURL("**/projects", { timeout: 10_000 });
    expect(page.url()).toContain("/projects");
  });

  test("should navigate to scans page via sidebar", async ({ page }) => {
    await page.goto("/dashboard");

    await page.click('a[href="/scans"]');
    await page.waitForURL("**/scans", { timeout: 10_000 });
    expect(page.url()).toContain("/scans");
  });

  test("should navigate to reports page via sidebar", async ({ page }) => {
    await page.goto("/dashboard");

    await page.click('a[href="/reports"]');
    await page.waitForURL("**/reports", { timeout: 10_000 });
    expect(page.url()).toContain("/reports");
  });

  test("should navigate to vulnerabilities page via sidebar", async ({ page }) => {
    await page.goto("/dashboard");

    await page.click('a[href="/vulnerabilities"]');
    await page.waitForURL("**/vulnerabilities", { timeout: 10_000 });
    expect(page.url()).toContain("/vulnerabilities");
  });

  test("should navigate to settings page via sidebar", async ({ page }) => {
    await page.goto("/dashboard");

    await page.click('a[href="/settings"]');
    await page.waitForURL("**/settings", { timeout: 10_000 });
    expect(page.url()).toContain("/settings");
  });

  test("should navigate to compare page via sidebar", async ({ page }) => {
    await page.goto("/dashboard");

    await page.click('a[href="/scans/compare"]');
    await page.waitForURL("**/scans/compare", { timeout: 10_000 });
    expect(page.url()).toContain("/scans/compare");
  });

  test("all protected routes should be accessible when authenticated", async ({ page }) => {
    const routes = ["/dashboard", "/projects", "/scans", "/reports", "/vulnerabilities", "/settings", "/scans/compare"];

    for (const route of routes) {
      await page.goto(route);
      // Should not redirect to login (since we're mocking auth)
      await page.waitForTimeout(1000);
      expect(page.url()).not.toContain("/login");
    }
  });
});
