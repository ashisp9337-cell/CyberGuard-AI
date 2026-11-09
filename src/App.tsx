import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AppProvider } from "@/context/AppContext";
import { ToastProvider } from "@/context/ToastContext";
import { AuthProvider } from "@/context/AuthContext";
import { AppShell } from "@/components/layout/AppShell";
import { ProtectedRoute } from "@/routes/ProtectedRoute";
import { ThreatoraWidget } from "@/components/chat/ThreatoraWidget";
import HomePage from "@/pages/HomePage";

// (31 Oct) every page except the home page is loaded only when it is first opened, so the first visit downloads
// much less JavaScript. The page code itself is unchanged.
const SignIn = lazy(() => import("@/pages/SignIn"));
const SignUp = lazy(() => import("@/pages/SignUp"));
const ForgotPassword = lazy(() => import("@/pages/ForgotPassword"));
const ResetPassword = lazy(() => import("@/pages/ResetPassword"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const ThreatOverview = lazy(() => import("@/pages/ThreatOverview"));
const LiveMonitoring = lazy(() => import("@/pages/LiveMonitoring"));
const PcNetwork = lazy(() => import("@/pages/PcNetwork"));
const Employees = lazy(() => import("@/pages/Employees"));
const Devices = lazy(() => import("@/pages/Devices"));
const ThreatIntelligence = lazy(() => import("@/pages/ThreatIntelligence"));
const ScanHistory = lazy(() => import("@/pages/ScanHistory"));
const Reports = lazy(() => import("@/pages/Reports"));
const Settings = lazy(() => import("@/pages/Settings"));
const Help = lazy(() => import("@/pages/Help"));
const ModulesLanding = lazy(() => import("@/pages/ModulesLanding"));
const ModuleOverview = lazy(() => import("@/pages/ModuleOverview"));
const AnalysisPage = lazy(() => import("@/pages/AnalysisPage"));
const NotFound = lazy(() => import("@/pages/NotFound"));

export default function App() {
  return (
    <AuthProvider>
      <AppProvider>
        <ToastProvider>
          <BrowserRouter>
            <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-sm text-slate-400" role="status">Loading…</div>}>
            <Routes>
              {/* Public pages — no AppShell, no authentication required */}
              <Route path="/" element={<HomePage />} />
              <Route path="signin" element={<SignIn />} />
              <Route path="signup" element={<SignUp />} />
              <Route path="forgot-password" element={<ForgotPassword />} />
              <Route path="reset-password" element={<ResetPassword />} />

              {/* Authenticated application — gated by ProtectedRoute, shares AppShell */}
              <Route element={<ProtectedRoute />}>
                <Route element={<AppShell />}>
                  <Route path="dashboard" element={<Dashboard />} />
                  <Route path="threat-overview" element={<ThreatOverview />} />
                  <Route path="live-monitoring" element={<LiveMonitoring />} />
                  <Route path="pc-network" element={<PcNetwork />} />
                  <Route path="employees" element={<Employees />} />
                  <Route path="devices" element={<Devices />} />
                  <Route path="threat-intelligence" element={<ThreatIntelligence />} />
                  <Route path="scan-history" element={<ScanHistory />} />
                  <Route path="reports" element={<Reports />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="help" element={<Help />} />
                  <Route path="modules" element={<ModulesLanding />} />
                  <Route path="modules/:moduleId" element={<ModuleOverview />} />
                  <Route path="modules/:moduleId/:subtopicId" element={<AnalysisPage />} />
                </Route>
              </Route>

              <Route path="*" element={<NotFound />} />
            </Routes>
            </Suspense>
            <ThreatoraWidget />
          </BrowserRouter>
        </ToastProvider>
      </AppProvider>
    </AuthProvider>
  );
}
