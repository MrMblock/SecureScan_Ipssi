import { test, expect } from "@playwright/test";

// Mock API responses
const mockUser = {
  email: "test@example.com",
  name: "Test User",
  avatar_url: null,
};

test.describe("Authentication", () => {
  test("should show login page", async ({ page }) => {
    await page.goto("/login");
    await expect(page.locator("text=SecureScan")).toBeVisible();
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
  });

  test("should redirect unauthenticated users to login", async ({ page }) => {
    // Mock 401 for /api/accounts/me/
    await page.route("**/api/accounts/me/", (route) =>
      route.fulfill({ status: 401, body: JSON.stringify({ detail: "Not authenticated" }) }),
    );

    await page.goto("/dashboard");
    // The app should redirect to login when not authenticated
    await page.waitForURL("**/login**", { timeout: 10_000 });
    expect(page.url()).toContain("/login");
  });

  test("should login successfully with valid credentials", async ({ page }) => {
    // Mock login endpoint
    await page.route("**/api/accounts/login/", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Login successful" }),
      }),
    );

    // Mock authenticated user
    await page.route("**/api/accounts/me/", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(mockUser),
      }),
    );

    // Mock other API calls on dashboard
    await page.route("**/api/scanner/**", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      }),
    );

    await page.goto("/login");
    await page.fill('input[type="email"]', "test@example.com");
    await page.fill('input[type="password"]', "password123");
    await page.click('button[type="submit"]');

    // Should redirect to dashboard after login
    await page.waitForURL("**/dashboard**", { timeout: 10_000 });
    expect(page.url()).toContain("/dashboard");
  });

  test("should show error on invalid login", async ({ page }) => {
    await page.route("**/api/accounts/login/", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Invalid credentials" }),
      }),
    );

    await page.goto("/login");
    await page.fill('input[type="email"]', "wrong@example.com");
    await page.fill('input[type="password"]', "wrongpassword");
    await page.click('button[type="submit"]');

    // Should stay on login page and show error
    await expect(page.locator("text=Invalid credentials").or(page.locator('[class*="error"], [class*="red"]'))).toBeVisible({ timeout: 5_000 });
  });
});
