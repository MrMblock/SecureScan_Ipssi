import "@testing-library/jest-dom/vitest";

// Polyfill ResizeObserver (Recharts)
globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// MSW
import { server } from "./src/test-utils/msw-server";

beforeAll(() => server.listen({ onUnhandledRequest: "warn" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
