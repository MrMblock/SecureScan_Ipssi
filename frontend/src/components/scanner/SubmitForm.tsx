"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import axios from "axios";
import api from "@/lib/api";
import { useTranslation } from "@/i18n";

type TabId = "git" | "zip" | "files";

interface GithubRepo {
  full_name: string;
  clone_url: string;
  private: boolean;
  language: string | null;
  updated_at: string;
}

export default function SubmitForm() {
  const router = useRouter();
  const { t } = useTranslation();

  const TABS: { id: TabId; label: string; icon: string }[] = [
    { id: "git", label: t("app.submitForm.gitUrl"), icon: "link" },
    { id: "zip", label: t("app.submitForm.zipArchive"), icon: "folder_zip" },
    { id: "files", label: t("app.submitForm.pasteCode"), icon: "content_paste" },
  ];

  const [activeTab, setActiveTab] = useState<TabId>("git");
  const [gitUrl, setGitUrl] = useState("");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [pastedCode, setPastedCode] = useState("");
  const [pastedFilename, setPastedFilename] = useState("main.py");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  // GitHub repos
  const [repos, setRepos] = useState<GithubRepo[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposLoaded, setReposLoaded] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);
  const [search, setSearch] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Fetch repos when git tab is active
  useEffect(() => {
    if (activeTab !== "git" || reposLoaded) return;
    setReposLoading(true);
    fetch("/api/accounts/github/repos/", {
      credentials: "include",
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (Array.isArray(data)) setRepos(data);
        setReposLoaded(true);
      })
      .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch GitHub repos", err); })
      .finally(() => setReposLoading(false));
  }, [activeTab, reposLoaded]);

  // Close dropdown on click outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node)
      ) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const filteredRepos = repos.filter((r) =>
    r.full_name.toLowerCase().includes(search.toLowerCase())
  );

  const selectRepo = (repo: GithubRepo) => {
    setGitUrl(repo.clone_url);
    setShowDropdown(false);
    setSearch("");
  };

  const clearError = () => setErrorMsg(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setLoading(true);

    try {
      const formData = new FormData();

      if (activeTab === "git") {
        if (!gitUrl.trim()) {
          setErrorMsg(t("app.submitForm.errorGitUrl"));
          return;
        }
        formData.append("source_type", "git");
        formData.append("source_url", gitUrl.trim());
      } else if (activeTab === "zip") {
        if (!zipFile) {
          setErrorMsg(t("app.submitForm.errorZip"));
          return;
        }
        formData.append("source_type", "zip");
        formData.append("source_file", zipFile);
      } else {
        if (!pastedCode.trim()) {
          setErrorMsg(t("app.submitForm.errorPasteCode"));
          return;
        }
        // Clean pasted code: strip trailing whitespace per line, then dedent
        const rawLines = pastedCode.split("\n").map((l) => l.trimEnd());
        const nonEmptyLines = rawLines.filter((l) => l.length > 0);
        const minIndent = nonEmptyLines.reduce((min, l) => {
          const match = l.match(/^(\s+)/);
          return match ? Math.min(min, match[1].length) : 0;
        }, Infinity);
        const cleanCode = minIndent > 0 && isFinite(minIndent)
          ? rawLines.map((l) => l.slice(minIndent)).join("\n")
          : rawLines.join("\n");
        const blob = new Blob([cleanCode], { type: "text/plain" });
        const file = new File([blob], pastedFilename || "code.txt", { type: "text/plain" });
        formData.append("source_type", "files");
        formData.append("source_file", file);
      }

      const response = await api.post("/api/scanner/scans/", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      router.push(`/scans/${response.data.id}`);
    } catch (err: unknown) {
      if (axios.isAxiosError(err)) {
        const data = err.response?.data;
        if (data) {
          if (typeof data === "string") {
            setErrorMsg(data);
          } else if (data.detail) {
            setErrorMsg(data.detail);
          } else {
            const messages = Object.values(data).flat().join(" ");
            setErrorMsg(
              messages || t("app.submitForm.errorValidation")
            );
          }
        } else {
          setErrorMsg(err.message || t("app.submitForm.errorNetwork"));
        }
      } else {
        setErrorMsg(t("app.submitForm.errorUnexpected"));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="rounded-xl border border-(--border) bg-(--bg-card) p-8">
      <h2 className="text-lg font-semibold text-(--text)">
        {t("app.submitForm.title")}
      </h2>
      <p className="mt-1 text-sm text-(--text-muted)">
        {t("app.submitForm.subtitle")}
      </p>

      {/* Tabs */}
      <div className="mt-6 flex gap-1 rounded-lg border border-(--border) bg-(--bg-main) p-1">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => {
              setActiveTab(tab.id);
              clearError();
            }}
            className={`flex flex-1 items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? "bg-(--bg-card) text-(--text) shadow-sm"
                : "text-(--text-muted) hover:text-(--text)"
            }`}
          >
            <span
              className="material-symbols-outlined text-base"
              aria-hidden
            >
              {tab.icon}
            </span>
            {tab.label}
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        {/* Git URL tab */}
        {activeTab === "git" && (
          <div className="space-y-3">
            {/* Repo selector */}
            {repos.length > 0 && (
              <div ref={dropdownRef} className="relative">
                <label className="mb-1.5 block text-sm font-medium text-(--text)">
                  {t("app.submitForm.importGithub")}
                </label>
                <button
                  type="button"
                  onClick={() => setShowDropdown(!showDropdown)}
                  className="flex w-full items-center justify-between rounded-lg border border-(--border) bg-(--bg-main) px-4 py-2.5 text-sm text-(--text) hover:border-(--accent)/50 transition cursor-pointer"
                >
                  <span className="flex items-center gap-2">
                    <svg
                      className="h-4 w-4"
                      viewBox="0 0 24 24"
                      fill="currentColor"
                    >
                      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
                    </svg>
                    {gitUrl
                      ? repos.find((r) => r.clone_url === gitUrl)?.full_name ||
                        t("app.submitForm.selectRepo")
                      : t("app.submitForm.selectRepo")}
                  </span>
                  <span className="material-symbols-outlined text-lg text-(--text-muted)">
                    {showDropdown ? "expand_less" : "expand_more"}
                  </span>
                </button>

                {showDropdown && (
                  <div className="absolute z-50 mt-1 w-full rounded-lg border border-(--border) bg-(--bg-card) shadow-xl">
                    <div className="p-2">
                      <input
                        type="text"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder={t("app.submitForm.searchRepos")}
                        className="w-full rounded-md border border-(--border) bg-(--bg-main) px-3 py-2 text-sm text-(--text) placeholder:text-(--text-muted) outline-none focus:border-(--accent)/50"
                        autoFocus
                      />
                    </div>
                    <ul className="max-h-64 overflow-y-auto py-1">
                      {filteredRepos.length === 0 ? (
                        <li className="px-4 py-3 text-sm text-(--text-muted) text-center">
                          {t("app.submitForm.noReposFound")}
                        </li>
                      ) : (
                        filteredRepos.map((repo) => (
                          <li key={repo.full_name}>
                            <button
                              type="button"
                              onClick={() => selectRepo(repo)}
                              className="flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm hover:bg-white/5 transition cursor-pointer"
                            >
                              <span className="material-symbols-outlined text-base text-(--text-muted)">
                                {repo.private ? "lock" : "public"}
                              </span>
                              <div className="min-w-0 flex-1">
                                <p className="truncate font-medium text-(--text)">
                                  {repo.full_name}
                                </p>
                                <p className="text-xs text-(--text-muted)">
                                  {repo.language || "Unknown"} ·{" "}
                                  {new Date(
                                    repo.updated_at
                                  ).toLocaleDateString()}
                                </p>
                              </div>
                            </button>
                          </li>
                        ))
                      )}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {reposLoading && (
              <p className="flex items-center gap-2 text-xs text-(--text-muted)">
                <span className="h-3 w-3 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                {t("app.submitForm.loadingRepos")}
              </p>
            )}

            {/* Manual URL input */}
            <div className="mt-3">
              <label
                htmlFor="git-url"
                className="block text-sm font-medium text-(--text)"
              >
                {repos.length > 0 ? t("app.submitForm.orEnterManually") : t("app.submitForm.repositoryUrl")}
              </label>
              <div className="mt-2 flex items-center gap-0 overflow-hidden rounded-lg border border-(--border) bg-(--bg-main) pr-2">
                <span
                  className="material-symbols-outlined flex shrink-0 px-3 text-(--text-muted)"
                  aria-hidden
                >
                  link
                </span>
                <input
                  id="git-url"
                  type="url"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  placeholder="https://github.com/organization/project.git"
                  className="min-w-0 flex-1 border-0 bg-transparent py-2.5 pl-0 pr-3 text-(--text) placeholder:text-(--text-muted) focus:ring-0 focus:ring-offset-0"
                  required
                  disabled={loading}
                />
              </div>
              <p className="mt-1.5 text-xs text-(--text-muted)">
                {t("app.submitForm.publicOnly")}
              </p>
            </div>
          </div>
        )}

        {/* ZIP archive tab */}
        {activeTab === "zip" && (
          <div>
            <label className="block text-sm font-medium text-(--text)">
              {t("app.submitForm.zipLabel")}
            </label>
            <div
              className={`mt-2 flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-8 text-center transition-colors ${
                dragOver
                  ? "border-(--accent) bg-blue-900/10"
                  : "border-(--border) bg-(--bg-main)"
              }`}
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                const file = e.dataTransfer.files?.[0];
                if (file) setZipFile(file);
              }}
            >
              <span
                className="material-symbols-outlined text-4xl text-(--text-muted)"
                aria-hidden
              >
                folder_zip
              </span>
              {zipFile ? (
                <div>
                  <p className="text-sm font-medium text-(--text)">
                    {zipFile.name}
                  </p>
                  <p className="text-xs text-(--text-muted)">
                    {(zipFile.size / 1024 / 1024).toFixed(1)} MB
                  </p>
                </div>
              ) : (
                <p className="text-sm text-(--text-muted)">
                  {t("app.submitForm.dragDrop")}
                </p>
              )}
              <label className="cursor-pointer rounded-md border border-(--border) bg-(--bg-card) px-4 py-2 text-sm text-(--text) hover:bg-white/5">
                {zipFile ? t("app.submitForm.changeFile") : t("app.submitForm.selectZip")}
                <input
                  type="file"
                  accept=".zip"
                  className="sr-only"
                  onChange={(e) => setZipFile(e.target.files?.[0] ?? null)}
                  disabled={loading}
                />
              </label>
            </div>
            <p className="mt-1.5 text-xs text-(--text-muted)">
              {t("app.submitForm.maxSize")}
            </p>
          </div>
        )}

        {/* Paste code tab */}
        {activeTab === "files" && (
          <div className="space-y-3">
            <div>
              <label htmlFor="paste-filename" className="block text-sm font-medium text-(--text)">
                {t("app.submitForm.filename")}
              </label>
              <input
                id="paste-filename"
                type="text"
                value={pastedFilename}
                onChange={(e) => setPastedFilename(e.target.value)}
                placeholder="e.g. main.py, index.js, app.go"
                className="mt-1.5 w-full rounded-lg border border-(--border) bg-(--bg-main) px-4 py-2.5 text-sm text-(--text) placeholder:text-(--text-muted) outline-none focus:border-(--accent)/50"
                disabled={loading}
              />
              <p className="mt-1 mb-2 text-xs text-(--text-muted)">
                {t("app.submitForm.fileExtHint")}
              </p>
            </div>
            <div>
              <label htmlFor="paste-code" className="block text-sm font-medium text-(--text)">
                {t("app.submitForm.code")}
              </label>
              <textarea
                id="paste-code"
                value={pastedCode}
                onChange={(e) => setPastedCode(e.target.value)}
                placeholder={t("app.submitForm.pastePlaceholder")}
                rows={12}
                className="mt-1.5 w-full rounded-lg border border-(--border) bg-(--bg-main) px-4 py-3 font-mono text-sm text-(--text) placeholder:text-(--text-muted) outline-none focus:border-(--accent)/50 resize-y"
                disabled={loading}
              />
            </div>
          </div>
        )}

        {/* Error message */}
        {errorMsg && (
          <div className="flex items-start gap-2 rounded-lg border border-red-800 bg-red-900/20 p-3 text-sm text-red-300">
            <span
              className="material-symbols-outlined shrink-0 text-base"
              aria-hidden
            >
              error
            </span>
            {errorMsg}
          </div>
        )}

        {/* Submit button */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-5 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-(--accent-hover) disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <span
                  className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white"
                  aria-hidden
                />
                {t("app.submitForm.submitting")}
              </>
            ) : (
              <>
                <span
                  className="material-symbols-outlined text-xl text-white"
                  aria-hidden
                >
                  rocket_launch
                </span>
                {activeTab === "git" ? t("app.submitForm.startAnalysis") : t("app.submitForm.uploadScan")}
              </>
            )}
          </button>
        </div>
      </form>
    </section>
  );
}
