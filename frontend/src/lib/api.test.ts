import { describe, it, expect, vi, beforeEach } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "@/test-utils/msw-server";
import api from "./api";

describe("api (Axios instance)", () => {
  beforeEach(() => {
    // Reset any overrides between tests
    server.resetHandlers();
  });

  it("passes through successful responses", async () => {
    server.use(
      http.get("/api/test/", () => {
        return HttpResponse.json({ ok: true });
      })
    );

    const res = await api.get("/api/test/");
    expect(res.data).toEqual({ ok: true });
    expect(res.status).toBe(200);
  });

  it("retries with refresh on 401, then succeeds", async () => {
    let callCount = 0;

    server.use(
      http.get("/api/protected/", () => {
        callCount++;
        if (callCount === 1) {
          return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
        }
        return HttpResponse.json({ data: "secret" });
      }),
      http.post("/api/accounts/token/refresh/", () => {
        return HttpResponse.json({ detail: "ok" });
      })
    );

    const res = await api.get("/api/protected/");
    expect(res.data).toEqual({ data: "secret" });
    expect(callCount).toBe(2);
  });

  it("rejects with 401 when refresh fails (redirect would follow in browser)", async () => {
    server.use(
      http.get("/api/protected/", () => {
        return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
      }),
      http.post("/api/accounts/token/refresh/", () => {
        return HttpResponse.json({ detail: "Invalid" }, { status: 401 });
      })
    );

    // The interceptor sets window.location.href = "/login" which is a no-op in jsdom.
    // The important behavior is that the promise rejects (doesn't retry infinitely).
    await expect(api.get("/api/protected/")).rejects.toThrow();
  });

  it("does not retry refresh endpoint itself", async () => {
    server.use(
      http.post("/api/accounts/token/refresh/", () => {
        return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
      })
    );

    await expect(
      api.post("/api/accounts/token/refresh/", {})
    ).rejects.toThrow();
  });

  it("sends cookies with requests (withCredentials)", () => {
    expect(api.defaults.withCredentials).toBe(true);
  });
});
