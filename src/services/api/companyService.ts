// (9 Nov) Company mode: the Employees page (administrators only) and invites.
import { useEffect, useState } from "react";
import { apiClient } from "./client";

export interface Employee {
  id: string;
  name: string;
  email: string;
  role: "admin" | "employee";
  owner: boolean;
  signIn: "Google" | "Password";
  active: boolean;
  online: boolean;
  createdAt: string | null;
  lastLogin: string | null;
  lastSeen: string | null;
  lastIp: string;
  lastBrowser: string;
  scans: number;
  threats: number;
  lastScan: string | null;
  failedSignIns7d: number;
  devices: number;
}

export interface EmployeesResponse {
  company: { name: string; domains: string[] };
  you: string;
  employees: Employee[];
  summary: { total: number; online: number; admins: number; disabled: number; openInvites: number; threats: number };
}

export interface EmployeeDetail {
  id: string;
  name: string;
  email: string;
  scans: { id: string; module: string; subtopic: string; target: string; risk: number; classification: string;
           threatType: string; at: string | null; source: string }[];
  signIns: { action: string; success: boolean; ip: string; browser: string; at: string | null }[];
}

export interface Invite {
  id: string;
  email: string;
  role: "admin" | "employee";
  status: "open" | "used" | "revoked" | "expired";
  createdAt: string | null;
  expiresAt: string | null;
  usedAt: string | null;
  link?: string;
  emailStatus?: string;
}

export interface CompanyPublic {
  name: string;
  domains: string[];
  restricted: boolean;
}

export const companyService = {
  publicInfo: () => apiClient.get<CompanyPublic>("/api/company/public"),
  employees: () => apiClient.get<EmployeesResponse>("/api/company/employees"),
  employee: (id: string) => apiClient.get<EmployeeDetail>(`/api/company/employees/${encodeURIComponent(id)}`),
  setRole: (id: string, role: "admin" | "employee") =>
    apiClient.post(`/api/company/employees/${encodeURIComponent(id)}/role`, { role }),
  setActive: (id: string, active: boolean) =>
    apiClient.post(`/api/company/employees/${encodeURIComponent(id)}/active`, { active }),
  signOut: (id: string) => apiClient.post(`/api/company/employees/${encodeURIComponent(id)}/sign-out`),
  invites: () => apiClient.get<{ invites: Invite[] }>("/api/company/invites"),
  invite: (email: string, role: "admin" | "employee") => apiClient.post<Invite>("/api/company/invites", { email, role }),
  revokeInvite: (id: string) => apiClient.delete<Invite>(`/api/company/invites/${encodeURIComponent(id)}`),
};

/** True when the signed-in account is an administrator (asked once per signed-in user; false while unknown). */
export function useIsAdmin(userId: string | undefined): boolean {
  const [admin, setAdmin] = useState(false);
  useEffect(() => {
    let alive = true;
    if (!userId) {
      setAdmin(false);
      return;
    }
    apiClient.get<{ isAdmin?: boolean }>("/api/auth/me")
      .then((me) => alive && setAdmin(me?.isAdmin === true))
      .catch(() => alive && setAdmin(false));
    return () => {
      alive = false;
    };
  }, [userId]);
  return admin;
}
