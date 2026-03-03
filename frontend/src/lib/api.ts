import axios from "axios";

const api = axios.create({
  withCredentials: true,
});

// Auto-refresh: on 401, try refreshing the token once via cookie, then retry
let refreshing: Promise<boolean> | null = null;

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;

    if (
      error.response?.status === 401 &&
      !original._retried &&
      typeof window !== "undefined" &&
      !original.url?.includes("/token/refresh/")
    ) {
      original._retried = true;

      if (!refreshing) {
        refreshing = (async () => {
          try {
            await axios.post(
              "/api/accounts/token/refresh/",
              {},
              { withCredentials: true },
            );
            return true;
          } catch {
            // Only redirect if not already on a public-ish page
            if (!window.location.pathname.startsWith("/login") && !window.location.pathname.startsWith("/signup")) {
              window.location.href = "/login";
            }
            return false;
          } finally {
            refreshing = null;
          }
        })();
      }

      const ok = await refreshing;
      if (ok) {
        return api(original);
      }
    }

    return Promise.reject(error);
  },
);

export default api;
