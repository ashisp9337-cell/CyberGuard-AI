import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// (7 Nov) fonts are bundled with the app: the page no longer waits for Google's font server (slow Wi-Fi = blank page)
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./index.css";
import App from "./App";
import { ThemeProvider } from "@/context/ThemeContext";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </StrictMode>
);
