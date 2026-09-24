// Centralized API configuration.
// All service modules read from here — never hardcode backend URLs in components.
//
// Set these in a `.env` file (see `.env.example`):
//   VITE_API_BASE_URL=http://localhost:8000   (dev)  or  https://api.yourdomain.com (prod)

export const API_CONFIG = {
  baseUrl: import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000",
  threatIntelligenceApi: import.meta.env.VITE_THREAT_INTELLIGENCE_API ?? "",
  authServiceUrl: import.meta.env.VITE_AUTH_SERVICE_URL ?? "",
  // When true, all services resolve from local mock data/generators instead
  // of issuing network requests — used for local UI-only development or demos
  // without a backend. Defaults to false now that a real backend exists;
  // set VITE_USE_MOCK_DATA=true to force mock mode.
  useMockData: import.meta.env.VITE_USE_MOCK_DATA === "true",
};
