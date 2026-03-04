import { http, HttpResponse } from "msw";

export const handlers = [
  // Default scan status
  http.get("/api/scanner/scans/:id/", () => {
    return HttpResponse.json({
      id: "test-scan-id",
      source_type: "git",
      source_url: "https://github.com/test/repo.git",
      source_filename: "",
      status: "completed",
      detected_languages: ["python"],
      error_message: "",
      created_at: "2025-01-01T00:00:00Z",
      completed_at: "2025-01-01T00:05:00Z",
      total_findings: 5,
      critical_count: 1,
      high_count: 2,
      medium_count: 1,
      low_count: 1,
      security_score: 72,
    });
  }),

  // Token refresh
  http.post("/api/accounts/token/refresh/", () => {
    return HttpResponse.json({ detail: "ok" });
  }),

  // GitHub repos
  http.get("/api/accounts/github/repos/", () => {
    return HttpResponse.json([
      {
        full_name: "user/repo-1",
        clone_url: "https://github.com/user/repo-1.git",
        private: false,
        language: "Python",
        updated_at: "2025-01-01T00:00:00Z",
      },
    ]);
  }),

  // Create scan
  http.post("/api/scanner/scans/", () => {
    return HttpResponse.json({ id: "new-scan-id" });
  }),

  // Fix endpoint
  http.post("/api/scanner/findings/:id/fix/", () => {
    return HttpResponse.json({
      fixed_code: "const safe = sanitize(input);",
      fix_explanation: "Sanitized user input",
      original_code: "const unsafe = input;",
      file_path: "src/app.js",
      line_start: 10,
      cached: false,
    });
  }),

  // Apply fix
  http.post("/api/scanner/findings/:id/apply/", () => {
    return HttpResponse.json({
      pr_url: "https://github.com/user/repo/pull/1",
      branch_name: "fix/test",
      commit_sha: "abc123",
      cached: false,
    });
  }),
];
