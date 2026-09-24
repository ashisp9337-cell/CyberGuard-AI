import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { ScanHistoryEntry } from "@/types";
import { listScans } from "@/services/api/scansService";
import { API_CONFIG } from "@/services/api/config";
import { useAuth } from "@/context/AuthContext";

const MONITORING_KEY = "cyberguard.monitoring.v1";

interface AppContextValue {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  mobileNavOpen: boolean;
  setMobileNavOpen: (open: boolean) => void;
  scanHistory: ScanHistoryEntry[];
  addScanToHistory: (entry: ScanHistoryEntry) => void;
  refreshScanHistory: () => void;
  monitoringActive: boolean;
  setMonitoringActive: (active: boolean) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [monitoringActive, setMonitoringActive] = useState<boolean>(() => {
    return localStorage.getItem(MONITORING_KEY) !== "false";
  });
  const { isAuthenticated } = useAuth();

  async function loadHistory() {
    if (API_CONFIG.useMockData) {
      const { generateScanHistory } = await import("@/services/mock/mockData");
      setScanHistory(generateScanHistory(28));
      return;
    }
    if (!isAuthenticated) {
      setScanHistory([]);
      return;
    }
    try {
      const { items } = await listScans({ pageSize: 200 });
      setScanHistory(items);
    } catch {
      // Leave whatever history is already in state — a transient fetch
      // failure shouldn't blank out the page.
    }
  }

  useEffect(() => {
    loadHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated]);

  useEffect(() => {
    localStorage.setItem(MONITORING_KEY, String(monitoringActive));
  }, [monitoringActive]);

  const addScanToHistory = (entry: ScanHistoryEntry) => {
    // Optimistic local prepend for instant feedback — the backend already
    // persisted this scan when the analysis call completed; refreshScanHistory()
    // will reconcile with the server's copy on next load.
    setScanHistory((prev) => [entry, ...prev].slice(0, 200));
  };

  return (
    <AppContext.Provider
      value={{
        sidebarCollapsed,
        toggleSidebar: () => setSidebarCollapsed((v) => !v),
        mobileNavOpen,
        setMobileNavOpen,
        scanHistory,
        addScanToHistory,
        refreshScanHistory: loadHistory,
        monitoringActive,
        setMonitoringActive,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useAppContext() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useAppContext must be used within AppProvider");
  return ctx;
}
