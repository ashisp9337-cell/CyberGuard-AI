import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AppProvider } from "@/context/AppContext";
import { ToastProvider } from "@/context/ToastContext";
import { AuthProvider } from "@/context/AuthContext";
import { AppShell } from "@/components/layout/AppShell";
import { ProtectedRoute } from "@/routes/ProtectedRoute";
import { ThreatoraWidget } from "@/components/chat/ThreatoraWidget";
import HomePage from "@/pages/HomePage";
import SignIn from "@/pages/SignIn";
import SignUp from "@/pages/SignUp";
import ForgotPassword from "@/pages/ForgotPassword";
import ResetPassword from "@/pages/ResetPassword";
import Dashboard from "@/pages/Dashboard";
import ThreatOverview from "@/pages/ThreatOverview";
import LiveMonitoring from "@/pages/LiveMonitoring";
import ThreatIntelligence from "@/pages/ThreatIntelligence";
import ScanHistory from "@/pages/ScanHistory";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";
import Help from "@/pages/Help";
import ModulesLanding from "@/pages/ModulesLanding";
import ModuleOverview from "@/pages/ModuleOverview";
import AnalysisPage from "@/pages/AnalysisPage";
import NotFound from "@/pages/NotFound";

export default function App() {
  return (
    <AuthProvider>
      <AppProvider>
        <ToastProvider>
          <BrowserRouter>
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
            <ThreatoraWidget />
          </BrowserRouter>
        </ToastProvider>
      </AppProvider>
    </AuthProvider>
  );
}
