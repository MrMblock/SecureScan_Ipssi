"use client";

import { useEffect, useState } from "react";
import toast, { Toaster } from "react-hot-toast";
import { useTranslation } from "@/i18n";

interface UserInfo {
  email: string;
  name: string;
  avatar_url: string | null;
}

const AI_PROVIDERS = [
  { value: "gemini", label: "Google Gemini", icon: "auto_awesome" },
  { value: "openai", label: "OpenAI", icon: "psychology" },
  { value: "anthropic", label: "Anthropic Claude", icon: "smart_toy" },
] as const;

type ProviderValue = (typeof AI_PROVIDERS)[number]["value"];

export default function SettingsPage() {
  const { t } = useTranslation();
  const [user, setUser] = useState<UserInfo | null>(null);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [avatar, setAvatar] = useState<File | null>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [aiProvider, setAiProvider] = useState<ProviderValue>("gemini");
  const [geminiKey, setGeminiKey] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");
  const [anthropicKey, setAnthropicKey] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetch("/api/accounts/me/", {
      credentials: "include",
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        setUser(data);
        setName(data.name || "");
        if (data.avatar_url) setAvatarPreview(data.avatar_url);
        if (data.ai_provider) setAiProvider(data.ai_provider);
        if (data.gemini_api_key) setGeminiKey(data.gemini_api_key);
        if (data.openai_api_key) setOpenaiKey(data.openai_api_key);
        if (data.anthropic_api_key) setAnthropicKey(data.anthropic_api_key);
      })
      .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch user settings", err); });
  }, []);

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setAvatar(file);
      setAvatarPreview(URL.createObjectURL(file));
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const body = new FormData();
      body.append("name", name);
      if (password) body.append("password", password);
      if (avatar) body.append("avatar", avatar);
      body.append("ai_provider", aiProvider);
      if (geminiKey && !geminiKey.startsWith("*")) body.append("gemini_api_key", geminiKey);
      if (openaiKey && !openaiKey.startsWith("*")) body.append("openai_api_key", openaiKey);
      if (anthropicKey && !anthropicKey.startsWith("*")) body.append("anthropic_api_key", anthropicKey);

      const res = await fetch("/api/accounts/me/", {
        method: "PATCH",
        credentials: "include",
        body,
      });
      if (!res.ok) throw new Error();
      const data = await res.json();
      setUser(data);
      setPassword("");
      setAvatar(null);
      if (data.avatar_url) setAvatarPreview(data.avatar_url);
      if (data.ai_provider) setAiProvider(data.ai_provider);
      toast.success(t("app.settings.successMessage"));
    } catch {
      toast.error(t("app.settings.errorMessage"));
    } finally {
      setSaving(false);
    }
  };

  if (!user) return null;

  const keyFields: Record<ProviderValue, { value: string; setter: (v: string) => void; keyName: string }> = {
    gemini: { value: geminiKey, setter: setGeminiKey, keyName: "geminiApiKey" },
    openai: { value: openaiKey, setter: setOpenaiKey, keyName: "openaiApiKey" },
    anthropic: { value: anthropicKey, setter: setAnthropicKey, keyName: "anthropicApiKey" },
  };

  const activeKey = keyFields[aiProvider];

  return (
    <>
      <Toaster
        position="top-center"
        toastOptions={{
          style: {
            background: "#0f1724",
            color: "#fff",
            border: "1px solid rgba(255,255,255,0.1)",
          },
        }}
      />
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-(--text)">{t("app.settings.title")}</h1>

        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8">
          <h2 className="mb-6 text-lg font-semibold text-(--text)">{t("app.settings.profile")}</h2>

          <div className="flex flex-col gap-6 max-w-md">
            {/* Avatar */}
            <div className="flex items-center gap-5">
              <label htmlFor="settings-avatar" className="cursor-pointer group">
                <div className="h-20 w-20 rounded-full border-2 border-dashed border-white/20 bg-white/5 flex items-center justify-center overflow-hidden group-hover:border-(--accent)/50 transition">
                  {avatarPreview ? (
                    <img
                      src={avatarPreview}
                      alt="avatar"
                      className="h-full w-full object-cover"
                    />
                  ) : (
                    <span className="material-symbols-outlined text-3xl text-white/30">
                      person
                    </span>
                  )}
                </div>
              </label>
              <input
                id="settings-avatar"
                type="file"
                accept="image/*"
                onChange={handleAvatarChange}
                className="hidden"
              />
              <div>
                <p className="text-sm font-medium text-(--text)">
                  {t("app.settings.profilePicture")}
                </p>
                <p className="text-xs text-(--text-muted)">
                  {t("app.settings.clickToChange")}
                </p>
              </div>
            </div>

            {/* Email (readonly) */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-(--text-muted)">
                {t("app.settings.email")}
              </label>
              <input
                type="email"
                value={user.email}
                disabled
                className="w-full rounded-lg border border-(--border) bg-white/5 px-4 py-2.5 text-(--text-muted) opacity-60 cursor-not-allowed"
              />
            </div>

            {/* Name */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-(--text-muted)">
                {t("app.settings.name")}
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-lg border border-(--border) bg-white/5 px-4 py-2.5 text-(--text) outline-none focus:border-(--accent)/50 transition"
              />
            </div>

            {/* Password */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-(--text-muted)">
                {t("app.settings.newPassword")}
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t("app.settings.passwordPlaceholder")}
                className="w-full rounded-lg border border-(--border) bg-white/5 px-4 py-2.5 text-(--text) placeholder-white/30 outline-none focus:border-(--accent)/50 transition"
              />
            </div>
          </div>
        </div>

        {/* AI Provider Section */}
        <div className="mt-4 mb-4 rounded-xl border border-(--border) bg-(--bg-card) p-8">
          <h2 className="mb-2 text-lg font-semibold text-(--text)">
            {t("app.settings.aiProvider")}
          </h2>
          <p className="mb-6 text-xs text-(--text-muted)">
            {t("app.settings.aiProviderHint")}
          </p>

          <div className="flex flex-col gap-6 max-w-md">
            {/* Provider selector */}
            <div className="relative">
              <select
                value={aiProvider}
                onChange={(e) => setAiProvider(e.target.value as ProviderValue)}
                className="w-full rounded-lg border border-(--border) bg-white/5 px-4 py-2.5 pr-10 text-(--text) outline-none focus:border-(--accent)/50 transition cursor-pointer appearance-none"
              >
                {AI_PROVIDERS.map((p) => (
                  <option key={p.value} value={p.value} className="bg-[#0f1724] text-white">
                    {p.label}
                  </option>
                ))}
              </select>
              <span className="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-sm text-(--text-muted) pointer-events-none">
                expand_more
              </span>
            </div>

            {/* Active provider API key */}
            <div>
              <label className="mb-1.5 block text-sm font-medium text-(--text-muted)">
                {t(`app.settings.${activeKey.keyName}`)}
              </label>
              <input
                type="password"
                value={activeKey.value}
                onChange={(e) => activeKey.setter(e.target.value)}
                placeholder={t(`app.settings.${activeKey.keyName}Placeholder`)}
                className="w-full rounded-lg border border-(--border) bg-white/5 px-4 py-2.5 text-(--text) placeholder-white/30 outline-none focus:border-(--accent)/50 transition"
              />
              <p className="mt-1 text-xs text-(--text-muted)">
                {t(`app.settings.${activeKey.keyName}Hint`)}
              </p>
            </div>
          </div>
        </div>

        {/* Save button */}
        <div className="flex">
          <button
            onClick={handleSave}
            disabled={saving}
            className="rounded-lg bg-(--accent) px-6 py-2.5 text-sm font-medium text-white hover:opacity-90 disabled:opacity-60 cursor-pointer transition"
          >
            {saving ? t("app.settings.saving") : t("app.settings.save")}
          </button>
        </div>
      </div>
    </>
  );
}
