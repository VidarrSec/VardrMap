"use client";

import { useEffect, useMemo, useState } from "react";
import { signIn, signOut } from "next-auth/react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ScopeItem = { id: string; value: string; kind: string; notes: string };
type ImportRecord = { id: string; tool_type: string; filename: string; imported_count: number };
type ReconItem = {
  id: string; source: string; url?: string; path?: string; host?: string;
  title?: string; status_code?: number; webserver?: string; port?: string | number;
  tech?: string[]; length?: number; words?: number; lines?: number;
  content_type?: string; notes?: string;
};
type ScanItem = {
  id: string; source: string; template_id: string; title: string;
  severity: string; asset: string; matched_at?: string; type?: string;
  description?: string; status: string;
};
type ManualTest = { id: string; title: string; hypothesis: string; payload: string; evidence: string; status: string };
type Finding = { id: string; title: string; severity: string; asset: string; status: string; summary: string; steps: string; impact: string; remediation: string };
type Report = { id: string; finding_id: string; title: string; summary: string; steps: string; impact: string; remediation: string; cwe: string; cvss: string; status: string };
type Program = {
  id: string; name: string; platform: string; program_url: string;
  scope_summary: string; severity_guidance: string; safe_harbor_notes: string;
  scope: { in: ScopeItem[]; out: ScopeItem[] };
  imports: ImportRecord[]; recon: ReconItem[]; scans: ScanItem[];
  manual_tests: ManualTest[]; findings: Finding[]; reports: Report[];
};
type Section = "dashboard" | "program" | "scope" | "imports" | "recon" | "scanning" | "manual" | "findings" | "reports";
type AppSession = {
  user?: { name?: string | null; email?: string | null; image?: string | null; githubId?: string; username?: string };
  backendToken?: string;
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

const EMPTY_PROGRAM: Program = {
  id: "", name: "", platform: "", program_url: "",
  scope_summary: "", severity_guidance: "", safe_harbor_notes: "",
  scope: { in: [], out: [] },
  imports: [], recon: [], scans: [], manual_tests: [], findings: [], reports: [],
};

// Nav items with icons
const NAV_ITEMS: { section: Section; label: string; icon: string }[] = [
  { section: "dashboard", label: "Dashboard", icon: "⬡" },
  { section: "program", label: "Program Profile", icon: "◈" },
  { section: "scope", label: "Scope", icon: "◎" },
  { section: "imports", label: "Imports", icon: "↓" },
  { section: "recon", label: "Recon", icon: "⊹" },
  { section: "scanning", label: "Scanning", icon: "◉" },
  { section: "manual", label: "Manual Testing", icon: "✦" },
  { section: "findings", label: "Findings", icon: "⚑" },
  { section: "reports", label: "Reports", icon: "◧" },
];

// ---------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase();
  const color =
    s === "critical" ? "bg-red-950 text-red-400 border-red-800" :
    s === "high"     ? "bg-orange-950 text-orange-400 border-orange-800" :
    s === "medium"   ? "bg-yellow-950 text-yellow-400 border-yellow-800" :
    s === "low"      ? "bg-blue-950 text-blue-400 border-blue-800" :
                       "bg-[#161616] text-[#6e6a86] border-[#2a2a3e]";
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider ${color}`}>
      {severity || "info"}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const s = status?.toLowerCase();
  const color =
    s === "validated" || s === "accepted" ? "bg-emerald-950 text-emerald-400 border-emerald-800" :
    s === "in_progress" || s === "triaged" ? "bg-emerald-950 text-emerald-400 border-emerald-800" :
    s === "closed" || s === "resolved"    ? "bg-[#161616] text-[#6e6a86] border-[#2a2a3e]" :
                                            "bg-[#161616] text-[#6b7280] border-[#2a2a3e]";
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider ${color}`}>
      {status || "—"}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Normalizer
// ---------------------------------------------------------------------------

function normalizeProgram(raw: any): Program {
  return {
    id: String(raw?.id ?? ""), name: String(raw?.name ?? ""),
    platform: String(raw?.platform ?? ""), program_url: String(raw?.program_url ?? ""),
    scope_summary: String(raw?.scope_summary ?? ""), severity_guidance: String(raw?.severity_guidance ?? ""),
    safe_harbor_notes: String(raw?.safe_harbor_notes ?? ""),
    scope: { in: Array.isArray(raw?.scope?.in) ? raw.scope.in : [], out: Array.isArray(raw?.scope?.out) ? raw.scope.out : [] },
    imports: Array.isArray(raw?.imports) ? raw.imports : [],
    recon: Array.isArray(raw?.recon) ? raw.recon : [],
    scans: Array.isArray(raw?.scans) ? raw.scans : [],
    manual_tests: Array.isArray(raw?.manual_tests) ? raw.manual_tests : [],
    findings: Array.isArray(raw?.findings) ? raw.findings : [],
    reports: Array.isArray(raw?.reports) ? raw.reports : [],
  };
}

async function getFrontendSession(): Promise<AppSession | null> {
  try {
    const res = await fetch("/api/auth/session", { method: "GET", credentials: "include", cache: "no-store" });
    if (!res.ok) return null;
    const session = await res.json();
    if (!session || Object.keys(session).length === 0) return null;
    return session;
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function Home() {
  const [session, setSession] = useState<AppSession | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [programs, setPrograms] = useState<Program[]>([]);
  const [selectedProgramId, setSelectedProgramId] = useState<string>("");
  const [activeSection, setActiveSection] = useState<Section>("dashboard");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const [newProgram, setNewProgram] = useState({ name: "", platform: "", program_url: "", scope_summary: "", severity_guidance: "", safe_harbor_notes: "" });
  const [programForm, setProgramForm] = useState({ name: "", platform: "", program_url: "", scope_summary: "", severity_guidance: "", safe_harbor_notes: "" });
  const [scopeIn, setScopeIn] = useState({ value: "", kind: "domain", notes: "" });
  const [scopeOut, setScopeOut] = useState({ value: "", kind: "domain", notes: "" });
  const [toolType, setToolType] = useState("ffuf");
  const [importFile, setImportFile] = useState<File | null>(null);
  const [manualTest, setManualTest] = useState({ title: "", hypothesis: "", payload: "", evidence: "", status: "new" });
  const [findingForm, setFindingForm] = useState({ title: "", severity: "medium", asset: "", status: "new", summary: "", steps: "", impact: "", remediation: "" });
  const [reportForm, setReportForm] = useState({ finding_id: "", title: "", summary: "", steps: "", impact: "", remediation: "", cwe: "", cvss: "", status: "draft" });

  const selectedProgram = useMemo(() => programs.find((p) => p.id === selectedProgramId) || null, [programs, selectedProgramId]);

  const workflowCounts = useMemo(() => {
    const p = selectedProgram ?? EMPTY_PROGRAM;
    return { inScope: p.scope?.in?.length ?? 0, recon: p.recon?.length ?? 0, scans: p.scans?.length ?? 0, manual: p.manual_tests?.length ?? 0, findings: p.findings?.length ?? 0, reports: p.reports?.length ?? 0 };
  }, [selectedProgram]);

  // Stage 3: backlinks — find which scans were promoted to each finding by matching title
  const backlinkMap = useMemo(() => {
    if (!selectedProgram) return {} as Record<string, ScanItem[]>;
    const map: Record<string, ScanItem[]> = {};
    for (const finding of selectedProgram.findings) {
      map[finding.id] = selectedProgram.scans.filter(
        (s) => s.title === finding.title || s.asset === finding.asset
      );
    }
    return map;
  }, [selectedProgram]);

  useEffect(() => { void bootstrapSession(); }, []);

  useEffect(() => {
    if (!authLoading && session?.backendToken) {
      void syncUser();
      void loadPrograms();
    }
  }, [authLoading, session?.backendToken]);

  useEffect(() => {
    if (selectedProgram) {
      setProgramForm({
        name: selectedProgram.name || "", platform: selectedProgram.platform || "",
        program_url: selectedProgram.program_url || "", scope_summary: selectedProgram.scope_summary || "",
        severity_guidance: selectedProgram.severity_guidance || "", safe_harbor_notes: selectedProgram.safe_harbor_notes || "",
      });
    }
  }, [selectedProgram]);

  // -------------------------------------------------------------------------
  // Auth
  // -------------------------------------------------------------------------

  async function bootstrapSession() {
    setAuthLoading(true);
    setSession(await getFrontendSession());
    setAuthLoading(false);
  }

  async function authFetch(path: string, init: RequestInit = {}) {
    const currentSession = session ?? (await getFrontendSession());
    if (!currentSession?.backendToken) throw new Error("Not authenticated");
    const headers = new Headers(init.headers || {});
    headers.set("Authorization", `Bearer ${currentSession.backendToken}`);
    if (!(init.body instanceof FormData) && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(`${API_URL}${path}`, { ...init, headers, cache: "no-store" });
    if (response.status === 401) { setMessage("Session expired. Please sign in again."); throw new Error("Unauthorized"); }
    return response;
  }

  // Fire-and-forget user sync on login
  async function syncUser() {
    try { await authFetch("/auth/sync", { method: "POST" }); } catch { /* non-blocking */ }
  }

  // -------------------------------------------------------------------------
  // Programs
  // -------------------------------------------------------------------------

  async function loadPrograms() {
    try {
      setMessage("");
      const res = await authFetch("/programs");
      if (!res.ok) throw new Error();
      const data = await res.json();
      const normalized = Array.isArray(data?.programs) ? data.programs.map(normalizeProgram) : [];
      setPrograms(normalized);
      if (!selectedProgramId && normalized.length > 0) setSelectedProgramId(normalized[0].id);
      if (normalized.length === 0) setSelectedProgramId("");
    } catch { setPrograms([]); setMessage("Failed to load programs."); }
  }

  async function refreshSelectedProgram(programId?: string) {
    const id = programId || selectedProgramId;
    if (!id) return;
    try {
      const res = await authFetch(`/programs/${id}`);
      if (!res.ok) throw new Error();
      const data = normalizeProgram(await res.json());
      setPrograms((prev) => prev.some((p) => p.id === id) ? prev.map((p) => p.id === id ? data : p) : [...prev, data]);
    } catch { setMessage("Failed to refresh program."); }
  }

  async function createProgram() {
    if (!newProgram.name.trim()) return;
    setLoading(true); setMessage("");
    try {
      const res = await authFetch("/programs", { method: "POST", body: JSON.stringify(newProgram) });
      if (!res.ok) throw new Error();
      const created = normalizeProgram(await res.json());
      setPrograms([...programs, created]);
      setSelectedProgramId(created.id);
      setNewProgram({ name: "", platform: "", program_url: "", scope_summary: "", severity_guidance: "", safe_harbor_notes: "" });
      setMessage("Program created.");
    } catch { setMessage("Failed to create program."); } finally { setLoading(false); }
  }

  async function saveProgramProfile() {
    if (!selectedProgramId) return;
    setLoading(true); setMessage("");
    try {
      const res = await authFetch(`/programs/${selectedProgramId}`, { method: "PATCH", body: JSON.stringify(programForm) });
      if (!res.ok) throw new Error();
      await refreshSelectedProgram();
      setMessage("Program saved.");
    } catch { setMessage("Failed to save program."); } finally { setLoading(false); }
  }

  async function deleteProgram() {
    if (!selectedProgramId || !confirm("Delete this program?")) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}`, { method: "DELETE" });
      if (!res.ok) throw new Error();
      const remaining = programs.filter((p) => p.id !== selectedProgramId);
      setPrograms(remaining);
      setSelectedProgramId(remaining[0]?.id || "");
      setMessage("Program deleted.");
    } catch { setMessage("Failed to delete program."); }
  }

  async function addScopeItem(scopeType: "in" | "out") {
    if (!selectedProgramId) return;
    const payload = scopeType === "in" ? scopeIn : scopeOut;
    if (!payload.value.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/scope/${scopeType}`, { method: "POST", body: JSON.stringify(payload) });
      if (!res.ok) throw new Error();
      if (scopeType === "in") setScopeIn({ value: "", kind: "domain", notes: "" });
      else setScopeOut({ value: "", kind: "domain", notes: "" });
      await refreshSelectedProgram();
      setMessage("Scope updated.");
    } catch { setMessage("Failed to add scope item."); }
  }

  async function deleteScopeItem(scopeType: "in" | "out", itemId: string) {
    if (!selectedProgramId) return;
    try {
      await authFetch(`/programs/${selectedProgramId}/scope/${scopeType}/${itemId}`, { method: "DELETE" });
      await refreshSelectedProgram();
      setMessage("Scope item deleted.");
    } catch { setMessage("Failed to delete scope item."); }
  }

  async function handleImport() {
    if (!selectedProgramId || !importFile) return;
    const formData = new FormData();
    formData.append("tool_type", toolType);
    formData.append("file", importFile);
    setLoading(true); setMessage("");
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/imports`, { method: "POST", body: formData });
      if (!res.ok) throw new Error();
      setImportFile(null);
      await refreshSelectedProgram();
      setMessage("Import complete.");
    } catch { setMessage("Import failed."); } finally { setLoading(false); }
  }

  async function addManualTest() {
    if (!selectedProgramId || !manualTest.title.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/manual-tests`, { method: "POST", body: JSON.stringify(manualTest) });
      if (!res.ok) throw new Error();
      setManualTest({ title: "", hypothesis: "", payload: "", evidence: "", status: "new" });
      await refreshSelectedProgram();
      setMessage("Manual test added.");
    } catch { setMessage("Failed to add manual test."); }
  }

  async function deleteManualTest(testId: string) {
    if (!selectedProgramId) return;
    try {
      await authFetch(`/programs/${selectedProgramId}/manual-tests/${testId}`, { method: "DELETE" });
      await refreshSelectedProgram();
      setMessage("Manual test deleted.");
    } catch { setMessage("Failed to delete manual test."); }
  }

  async function addFinding() {
    if (!selectedProgramId || !findingForm.title.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/findings`, { method: "POST", body: JSON.stringify(findingForm) });
      if (!res.ok) throw new Error();
      setFindingForm({ title: "", severity: "medium", asset: "", status: "new", summary: "", steps: "", impact: "", remediation: "" });
      await refreshSelectedProgram();
      setMessage("Finding added.");
    } catch { setMessage("Failed to add finding."); }
  }

  async function deleteFinding(findingId: string) {
    if (!selectedProgramId) return;
    try {
      await authFetch(`/programs/${selectedProgramId}/findings/${findingId}`, { method: "DELETE" });
      await refreshSelectedProgram();
      setMessage("Finding deleted.");
    } catch { setMessage("Failed to delete finding."); }
  }

  async function addReport() {
    if (!selectedProgramId || !reportForm.title.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/reports`, { method: "POST", body: JSON.stringify(reportForm) });
      if (!res.ok) throw new Error();
      setReportForm({ finding_id: "", title: "", summary: "", steps: "", impact: "", remediation: "", cwe: "", cvss: "", status: "draft" });
      await refreshSelectedProgram();
      setMessage("Report saved.");
    } catch { setMessage("Failed to save report."); }
  }

  async function deleteReport(reportId: string) {
    if (!selectedProgramId) return;
    try {
      await authFetch(`/programs/${selectedProgramId}/reports/${reportId}`, { method: "DELETE" });
      await refreshSelectedProgram();
      setMessage("Report deleted.");
    } catch { setMessage("Failed to delete report."); }
  }

  function promoteScanToFinding(scan: ScanItem) {
    setActiveSection("findings");
    setFindingForm({ title: scan.title, severity: scan.severity || "medium", asset: scan.asset || "", status: "candidate", summary: scan.description || "", steps: "", impact: "", remediation: "" });
  }

  function generateReportPreview() {
    return `# ${reportForm.title || "Untitled Report"}\n\n## Summary\n${reportForm.summary || ""}\n\n## Steps to Reproduce\n${reportForm.steps || ""}\n\n## Impact\n${reportForm.impact || ""}\n\n## Remediation\n${reportForm.remediation || ""}\n\n## CWE\n${reportForm.cwe || ""}\n\n## CVSS\n${reportForm.cvss || ""}`;
  }

  const isErrorMessage = message.toLowerCase().includes("fail") || message.toLowerCase().includes("error") || message.toLowerCase().includes("expired");

  // -------------------------------------------------------------------------
  // Loading / login screens
  // -------------------------------------------------------------------------

  if (authLoading) {
    return (
      <main className="min-h-screen bg-[#161616] text-[#f1f5f9] flex items-center justify-center">
        <div className="flex items-center gap-3 text-[#52525b]">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#7f849c]" />
          <span className="text-sm tracking-wide font-mono">initializing…</span>
        </div>
      </main>
    );
  }

  if (!session?.backendToken) {
    return (
      <main className="min-h-screen bg-[#161616] text-[#f1f5f9] flex items-center justify-center p-6">
        <div className="w-full max-w-sm rounded-2xl border border-[#2e2e2e] bg-[#1a1a1a] p-10 text-center shadow-2xl">
          <div className="mx-auto mb-5 flex h-10 w-10 items-center justify-center rounded-xl bg-[#2e2e2e] text-[#f59e0b]">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">VardrMap</h1>
          <p className="mt-2 text-sm text-[#52525b]">Sign in with GitHub to access your private bug bounty workspace.</p>
          <button onClick={() => signIn("github")} className="mt-7 w-full rounded-lg bg-[#f59e0b] px-4 py-2.5 text-sm font-semibold text-[#161616] transition hover:bg-[#fbbf24] active:scale-[0.98]">
            Sign in with GitHub
          </button>
        </div>
      </main>
    );
  }

  // -------------------------------------------------------------------------
  // App shell
  // -------------------------------------------------------------------------

  return (
    <main className="min-h-screen bg-[#161616] text-[#f1f5f9]">
      <div className={`grid min-h-screen transition-all duration-200 ${sidebarCollapsed ? "grid-cols-1 lg:grid-cols-[52px_1fr]" : "grid-cols-1 lg:grid-cols-[240px_1fr]"}`}>

        {/* Sidebar */}
        <aside className="flex flex-col border-r border-[#2e2e2e] bg-[#1a1a1a] overflow-hidden">

          {/* Brand row */}
          <div className="flex items-center justify-between gap-2 border-b border-[#2e2e2e] px-3 py-4">
            {!sidebarCollapsed && (
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-[#f1f5f9]">VardrMap</span>
                  <span className="rounded bg-[#2e2e2e] px-1.5 py-0.5 font-mono text-[9px] text-[#52525b]">BETA</span>
                </div>
                <p className="mt-0.5 truncate text-[10px] text-[#52525b]">
                  {session.user?.username || session.user?.email || "GitHub user"}
                </p>
              </div>
            )}
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="flex-shrink-0 rounded-md p-1.5 text-[#52525b] transition hover:bg-[#2e2e2e] hover:text-[#f1f5f9]"
              title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                {sidebarCollapsed ? <><polyline points="9 18 15 12 9 6" /></> : <><polyline points="15 18 9 12 15 6" /></>}
              </svg>
            </button>
          </div>

          {/* Program selector */}
          {!sidebarCollapsed && (
            <div className="border-b border-[#2e2e2e] px-3 py-3">
              <label className="mb-1.5 block text-[9px] font-semibold uppercase tracking-widest text-[#52525b]">Active Program</label>
              <select
                className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-2.5 py-1.5 text-xs text-[#f1f5f9] transition focus:border-[#f59e0b] focus:outline-none"
                value={selectedProgramId}
                onChange={(e) => setSelectedProgramId(e.target.value)}
              >
                <option value="">Choose a program</option>
                {programs.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
          )}

          {/* Nav */}
          <nav className="flex-1 space-y-0.5 px-2 py-3">
            {NAV_ITEMS.map(({ section, label, icon }) => (
              <button
                key={section}
                onClick={() => setActiveSection(section)}
                className={`group relative flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-all duration-150 ${
                  activeSection === section
                    ? "bg-[#f59e0b]/10 text-[#f59e0b] font-semibold"
                    : "text-[#52525b] hover:bg-[#242424] hover:text-[#94a3b8]"
                }`}
                title={sidebarCollapsed ? label : undefined}
              >
                {activeSection === section && (
                  <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-[#f59e0b]" />
                )}
                <span className="flex-shrink-0 font-mono text-xs text-[#f59e0b]">{icon}</span>
                {!sidebarCollapsed && <span className="text-xs font-medium">{label}</span>}
              </button>
            ))}
          </nav>

          {/* Create program + sign out */}
          {!sidebarCollapsed && (
            <div className="border-t border-[#2e2e2e] px-3 py-4 space-y-2">
              <p className="text-[9px] font-semibold uppercase tracking-widest text-[#52525b]">New Program</p>
              <input
                className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-2.5 py-1.5 text-xs text-[#f1f5f9] placeholder-[#3a3a3a] transition focus:border-[#f59e0b] focus:outline-none"
                placeholder="Program name"
                value={newProgram.name}
                onChange={(e) => setNewProgram({ ...newProgram, name: e.target.value })}
              />
              <input
                className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-2.5 py-1.5 text-xs text-[#f1f5f9] placeholder-[#3a3a3a] transition focus:border-[#f59e0b] focus:outline-none"
                placeholder="Platform"
                value={newProgram.platform}
                onChange={(e) => setNewProgram({ ...newProgram, platform: e.target.value })}
              />
              <input
                className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-2.5 py-1.5 text-xs text-[#f1f5f9] placeholder-[#3a3a3a] transition focus:border-[#f59e0b] focus:outline-none"
                placeholder="Program URL"
                value={newProgram.program_url}
                onChange={(e) => setNewProgram({ ...newProgram, program_url: e.target.value })}
              />
              <button onClick={createProgram} disabled={loading} className="w-full rounded-md bg-[#f59e0b] px-3 py-1.5 text-xs font-semibold text-[#161616] transition hover:bg-[#fbbf24] active:scale-[0.98] disabled:opacity-50">
                {loading ? "Working…" : "Create Program"}
              </button>
              <button onClick={() => signOut({ callbackUrl: "/" })} className="w-full rounded-md border border-[#2e2e2e] px-3 py-1.5 text-xs text-[#52525b] transition hover:border-[#3a3a3a] hover:text-[#94a3b8]">
                Sign out
              </button>
            </div>
          )}
        </aside>

        {/* Main content */}
        <section className="min-w-0 overflow-auto p-6 lg:p-8">

          {/* Message banner */}
          {message && (
            <div className={`mb-5 flex items-center gap-2.5 rounded-lg border px-4 py-3 text-sm ${
              isErrorMessage
                ? "border-red-900 bg-red-950/30 text-red-300"
                : "border-[#a6e3a1]/20 bg-[#a6e3a1]/5 text-[#a6e3a1]"
            }`}>
              <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${isErrorMessage ? "bg-red-400" : "bg-[#a6e3a1]"}`} />
              {message}
            </div>
          )}

          {!selectedProgram && (
            <div className="rounded-2xl border border-dashed border-[#2e2e2e] p-14 text-center">
              <p className="text-sm text-[#3a3a3a]">Create or select a program to begin.</p>
            </div>
          )}

          {/* Dashboard */}
          {selectedProgram && activeSection === "dashboard" && (
            <div className="space-y-7">
              <SectionHeader title={selectedProgram.name} description="Select a program, confirm scope, import tool output, review recon, validate findings, and draft a report." />
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <DashboardCard title="In-Scope Assets" value={workflowCounts.inScope} accent="#f59e0b" />
                <DashboardCard title="Recon Entries" value={workflowCounts.recon} accent="#89b4fa" />
                <DashboardCard title="Scan Results" value={workflowCounts.scans} accent="#f38ba8" />
                <DashboardCard title="Manual Tests" value={workflowCounts.manual} accent="#fab387" />
                <DashboardCard title="Findings" value={workflowCounts.findings} accent="#f9e2af" />
                <DashboardCard title="Reports" value={workflowCounts.reports} accent="#a6e3a1" />
              </div>
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="Program Snapshot">
                  <KeyValue label="Platform" value={selectedProgram.platform || "—"} />
                  <KeyValue label="Program URL" value={selectedProgram.program_url || "—"} />
                  <KeyValue label="Scope Summary" value={selectedProgram.scope_summary || "—"} />
                  <KeyValue label="Severity Guidance" value={selectedProgram.severity_guidance || "—"} />
                  <KeyValue label="Safe Harbor" value={selectedProgram.safe_harbor_notes || "—"} />
                </Panel>
                <Panel title="Imports Summary">
                  {selectedProgram.imports.length === 0 ? (
                    <p className="text-sm text-[#3a3a3a]">No imports yet.</p>
                  ) : (
                    <div className="space-y-2">
                      {selectedProgram.imports.map((item) => (
                        <div key={item.id} className="flex items-center justify-between rounded-lg border border-[#2e2e2e] bg-[#161616] px-4 py-3">
                          <span className="font-mono text-xs font-semibold text-[#f59e0b] uppercase">{item.tool_type}</span>
                          <span className="text-xs text-[#52525b]">{item.imported_count} records</span>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </div>
          )}

          {/* Program Profile */}
          {selectedProgram && activeSection === "program" && (
            <div className="space-y-7">
              <SectionHeader title="Program Profile" description="Track target program details, policies, and notes." />
              <Panel title="Edit Program">
                <div className="grid gap-4 md:grid-cols-2">
                  <Input label="Program Name" value={programForm.name} onChange={(v) => setProgramForm({ ...programForm, name: v })} />
                  <Input label="Platform" value={programForm.platform} onChange={(v) => setProgramForm({ ...programForm, platform: v })} />
                  <Input label="Program URL" value={programForm.program_url} onChange={(v) => setProgramForm({ ...programForm, program_url: v })} />
                  <Input label="Severity Guidance" value={programForm.severity_guidance} onChange={(v) => setProgramForm({ ...programForm, severity_guidance: v })} />
                </div>
                <div className="mt-4 grid gap-4">
                  <Textarea label="Scope Summary" value={programForm.scope_summary} onChange={(v) => setProgramForm({ ...programForm, scope_summary: v })} />
                  <Textarea label="Safe Harbor Notes" value={programForm.safe_harbor_notes} onChange={(v) => setProgramForm({ ...programForm, safe_harbor_notes: v })} />
                </div>
                <div className="mt-5 flex gap-3">
                  <PrimaryButton onClick={saveProgramProfile} label="Save Profile" />
                  <DangerButton onClick={deleteProgram} label="Delete Program" />
                </div>
              </Panel>
            </div>
          )}

          {/* Scope */}
          {selectedProgram && activeSection === "scope" && (
            <div className="space-y-7">
              <SectionHeader title="Scope" description="Keep clear in-scope and out-of-scope boundaries before testing." />
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="In-Scope Assets">
                  <div className="grid gap-3">
                    <Input label="Value" value={scopeIn.value} onChange={(v) => setScopeIn({ ...scopeIn, value: v })} />
                    <Input label="Kind" value={scopeIn.kind} onChange={(v) => setScopeIn({ ...scopeIn, kind: v })} />
                    <Textarea label="Notes" value={scopeIn.notes} onChange={(v) => setScopeIn({ ...scopeIn, notes: v })} />
                    <PrimaryButton onClick={() => addScopeItem("in")} label="Add In-Scope Asset" />
                  </div>
                  <div className="mt-5 space-y-2">
                    {(selectedProgram.scope?.in ?? []).map((item) => (
                      <ListCard key={item.id} title={item.value} subtitle={`${item.kind}${item.notes ? ` — ${item.notes}` : ""}`} onDelete={() => deleteScopeItem("in", item.id)} />
                    ))}
                  </div>
                </Panel>
                <Panel title="Out-of-Scope Assets">
                  <div className="grid gap-3">
                    <Input label="Value" value={scopeOut.value} onChange={(v) => setScopeOut({ ...scopeOut, value: v })} />
                    <Input label="Kind" value={scopeOut.kind} onChange={(v) => setScopeOut({ ...scopeOut, kind: v })} />
                    <Textarea label="Notes" value={scopeOut.notes} onChange={(v) => setScopeOut({ ...scopeOut, notes: v })} />
                    <PrimaryButton onClick={() => addScopeItem("out")} label="Add Out-of-Scope Asset" />
                  </div>
                  <div className="mt-5 space-y-2">
                    {(selectedProgram.scope?.out ?? []).map((item) => (
                      <ListCard key={item.id} title={item.value} subtitle={`${item.kind}${item.notes ? ` — ${item.notes}` : ""}`} onDelete={() => deleteScopeItem("out", item.id)} />
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}

          {/* Imports */}
          {selectedProgram && activeSection === "imports" && (
            <div className="space-y-7">
              <SectionHeader title="Imports" description="Upload tool output instead of manually typing recon data." />
              <Panel title="Import Tool Output">
                <div className="grid gap-4 md:grid-cols-3">
                  <div>
                    <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-[#52525b]">Tool Type</label>
                    <select className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-2.5 py-2 text-sm text-[#f1f5f9] transition focus:border-[#f59e0b] focus:outline-none" value={toolType} onChange={(e) => setToolType(e.target.value)}>
                      <option value="ffuf">ffuf</option>
                      <option value="httpx">httpx</option>
                      <option value="nuclei">nuclei</option>
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-[#52525b]">JSON / JSONL File</label>
                    <input type="file" accept=".json,.jsonl,application/json,application/x-ndjson" onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                      className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-2.5 py-2 text-sm text-[#52525b] file:mr-3 file:rounded file:border-0 file:bg-[#2e2e2e] file:px-2.5 file:py-1 file:text-xs file:font-semibold file:text-[#f1f5f9]" />
                  </div>
                </div>
                <div className="mt-5"><PrimaryButton onClick={handleImport} label={loading ? "Importing…" : "Import Results"} /></div>
                <div className="mt-6 rounded-xl border border-[#2e2e2e] bg-[#161616] p-4">
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-[#52525b]">Supported imports</p>
                  <div className="space-y-1 text-xs text-[#52525b]">
                    <p><span className="font-mono text-[#f59e0b]">ffuf</span> — Recon endpoints and paths</p>
                    <p><span className="font-mono text-[#f59e0b]">httpx</span> — Live hosts, titles, technologies</p>
                    <p><span className="font-mono text-[#f59e0b]">nuclei</span> — Candidate scan findings</p>
                  </div>
                </div>
              </Panel>
            </div>
          )}

          {/* Recon */}
          {selectedProgram && activeSection === "recon" && (
            <div className="space-y-7">
              <SectionHeader title="Recon" description="Review discovered subdomains, endpoints, paths, and technologies." />
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="Discovered Assets">
                  {(selectedProgram.recon ?? []).length === 0 ? (
                    <p className="text-sm text-[#3a3a3a]">No recon data imported yet.</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="min-w-full text-xs">
                        <thead>
                          <tr className="border-b border-[#2e2e2e]">
                            {["Source","URL / Host","Path / Title","Status"].map((h) => (
                              <th key={h} className="pb-2.5 pr-4 text-left text-[9px] font-semibold uppercase tracking-widest text-[#52525b]">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {(selectedProgram.recon ?? []).map((item, i) => (
                            <tr key={item.id} className={`border-b border-[#161616] ${i % 2 === 0 ? "" : "bg-[#1a1a1a]/40"}`}>
                              <td className="py-2.5 pr-4 font-mono text-[#52525b]">{item.source}</td>
                              <td className="py-2.5 pr-4 max-w-[180px] truncate text-[#f1f5f9]">{item.url || item.host || "—"}</td>
                              <td className="py-2.5 pr-4 max-w-[160px] truncate text-[#6b7280]">{item.path || item.title || "—"}</td>
                              <td className="py-2.5 font-mono text-[#52525b]">{item.status_code || "—"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Panel>
                <Panel title="Technology / Metadata">
                  <div className="space-y-2">
                    {(selectedProgram.recon ?? []).map((item) => (
                      <div key={item.id} className="rounded-lg border border-[#2e2e2e] bg-[#161616] px-4 py-3">
                        <div className="text-sm font-medium text-[#f1f5f9]">{item.url || item.host || "Unknown"}</div>
                        <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-[#52525b]">
                          <span>Server: <span className="text-[#6b7280]">{item.webserver || "—"}</span></span>
                          <span>Tech: <span className="text-[#6b7280]">{Array.isArray(item.tech) ? item.tech.join(", ") || "—" : "—"}</span></span>
                          <span>L/W/Li: <span className="font-mono text-[#6b7280]">{item.length || 0}/{item.words || 0}/{item.lines || 0}</span></span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}

          {/* Scanning */}
          {selectedProgram && activeSection === "scanning" && (
            <div className="space-y-7">
              <SectionHeader title="Scanning" description="Review candidate vulnerabilities from imported scan results." />
              <Panel title="Nuclei Candidates">
                {(selectedProgram.scans ?? []).length === 0 ? (
                  <p className="text-sm text-[#3a3a3a]">No scan results imported yet.</p>
                ) : (
                  <div className="space-y-3">
                    {(selectedProgram.scans ?? []).map((scan) => (
                      <div key={scan.id} className="rounded-xl border border-[#2e2e2e] bg-[#161616] p-4">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="font-semibold text-[#f1f5f9]">{scan.title}</div>
                            <div className="mt-1 font-mono text-xs text-[#52525b]">{scan.asset || "Unknown"} · {scan.template_id}</div>
                          </div>
                          <div className="flex flex-shrink-0 items-center gap-2">
                            <SeverityBadge severity={scan.severity} />
                            <button onClick={() => promoteScanToFinding(scan)} className="rounded-md border border-[#2e2e2e] bg-[#242424] px-3 py-1.5 text-xs font-semibold text-[#f59e0b] transition hover:border-[#f59e0b]/30 hover:bg-[#2e2e2e]">
                              Promote →
                            </button>
                          </div>
                        </div>
                        {scan.description && <p className="mt-3 text-sm text-[#6b7280]">{scan.description}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </div>
          )}

          {/* Manual Testing */}
          {selectedProgram && activeSection === "manual" && (
            <div className="space-y-7">
              <SectionHeader title="Manual Testing" description="Track hypotheses, payloads, exploitation notes, and evidence." />
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="Add Manual Test Note">
                  <div className="grid gap-3">
                    <Input label="Title" value={manualTest.title} onChange={(v) => setManualTest({ ...manualTest, title: v })} />
                    <Textarea label="Hypothesis" value={manualTest.hypothesis} onChange={(v) => setManualTest({ ...manualTest, hypothesis: v })} />
                    <Textarea label="Payload / Request Notes" value={manualTest.payload} onChange={(v) => setManualTest({ ...manualTest, payload: v })} />
                    <Textarea label="Evidence" value={manualTest.evidence} onChange={(v) => setManualTest({ ...manualTest, evidence: v })} />
                    <Input label="Status" value={manualTest.status} onChange={(v) => setManualTest({ ...manualTest, status: v })} />
                    <PrimaryButton onClick={addManualTest} label="Save Manual Test" />
                  </div>
                </Panel>
                <Panel title="Saved Manual Tests">
                  {(selectedProgram.manual_tests ?? []).length === 0 ? (
                    <p className="text-sm text-[#3a3a3a]">No manual tests saved yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {(selectedProgram.manual_tests ?? []).map((test) => (
                        <div key={test.id} className="rounded-xl border border-[#2e2e2e] bg-[#161616] p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="font-semibold text-[#f1f5f9]">{test.title}</div>
                              <div className="mt-1"><StatusBadge status={test.status} /></div>
                            </div>
                            <DangerButton onClick={() => deleteManualTest(test.id)} label="Delete" small />
                          </div>
                          {test.hypothesis && <p className="mt-3 text-sm text-[#6b7280]">{test.hypothesis}</p>}
                          {test.payload && <p className="mt-2 font-mono text-xs text-[#52525b]">Payload: {test.payload}</p>}
                          {test.evidence && <p className="mt-1 text-xs text-[#52525b]">Evidence: {test.evidence}</p>}
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </div>
          )}

          {/* Findings */}
          {selectedProgram && activeSection === "findings" && (
            <div className="space-y-7">
              <SectionHeader title="Findings" description="Track validated issues before drafting the final report." />
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="Add Finding">
                  <div className="grid gap-3">
                    <Input label="Title" value={findingForm.title} onChange={(v) => setFindingForm({ ...findingForm, title: v })} />
                    <div className="grid gap-3 md:grid-cols-3">
                      <Input label="Severity" value={findingForm.severity} onChange={(v) => setFindingForm({ ...findingForm, severity: v })} />
                      <Input label="Asset" value={findingForm.asset} onChange={(v) => setFindingForm({ ...findingForm, asset: v })} />
                      <Input label="Status" value={findingForm.status} onChange={(v) => setFindingForm({ ...findingForm, status: v })} />
                    </div>
                    <Textarea label="Summary" value={findingForm.summary} onChange={(v) => setFindingForm({ ...findingForm, summary: v })} />
                    <Textarea label="Steps" value={findingForm.steps} onChange={(v) => setFindingForm({ ...findingForm, steps: v })} />
                    <Textarea label="Impact" value={findingForm.impact} onChange={(v) => setFindingForm({ ...findingForm, impact: v })} />
                    <Textarea label="Remediation" value={findingForm.remediation} onChange={(v) => setFindingForm({ ...findingForm, remediation: v })} />
                    <PrimaryButton onClick={addFinding} label="Save Finding" />
                  </div>
                </Panel>
                <Panel title="Finding Tracker">
                  {(selectedProgram.findings ?? []).length === 0 ? (
                    <p className="text-sm text-[#3a3a3a]">No findings yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {(selectedProgram.findings ?? []).map((finding) => (
                        <div key={finding.id} className="rounded-xl border border-[#2e2e2e] bg-[#161616] p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="font-semibold text-[#f1f5f9]">{finding.title}</div>
                              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                                <SeverityBadge severity={finding.severity} />
                                <StatusBadge status={finding.status} />
                                {finding.asset && <span className="font-mono text-xs text-[#52525b]">{finding.asset}</span>}
                              </div>
                              {/* Stage 3: Backlinks */}
                              {backlinkMap[finding.id]?.length > 0 && (
                                <div className="mt-2 flex flex-wrap gap-1">
                                  {backlinkMap[finding.id].map((scan) => (
                                    <span key={scan.id} className="inline-flex items-center gap-1 rounded border border-[#f59e0b]/20 bg-[#f59e0b]/5 px-1.5 py-0.5 font-mono text-[9px] text-[#f59e0b]">
                                      ↖ {scan.template_id || scan.title}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                            <DangerButton onClick={() => deleteFinding(finding.id)} label="Delete" small />
                          </div>
                          {finding.summary && <p className="mt-3 text-sm text-[#6b7280]">{finding.summary}</p>}
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </div>
          )}

          {/* Reports */}
          {selectedProgram && activeSection === "reports" && (
            <div className="space-y-7">
              <SectionHeader title="Reports" description="Draft submission-ready reports from validated findings." />
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="Draft Report">
                  <div className="grid gap-3">
                    <div>
                      <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-[#52525b]">Link Finding</label>
                      <select
                        className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-2.5 py-2 text-sm text-[#f1f5f9] transition focus:border-[#f59e0b] focus:outline-none"
                        value={reportForm.finding_id}
                        onChange={(e) => {
                          const fid = e.target.value;
                          const f = (selectedProgram.findings ?? []).find((x) => x.id === fid);
                          setReportForm({ ...reportForm, finding_id: fid, title: f?.title || reportForm.title, summary: f?.summary || reportForm.summary, steps: f?.steps || reportForm.steps, impact: f?.impact || reportForm.impact, remediation: f?.remediation || reportForm.remediation });
                        }}
                      >
                        <option value="">No linked finding</option>
                        {(selectedProgram.findings ?? []).map((f) => <option key={f.id} value={f.id}>{f.title}</option>)}
                      </select>
                    </div>
                    <Input label="Report Title" value={reportForm.title} onChange={(v) => setReportForm({ ...reportForm, title: v })} />
                    <Textarea label="Summary" value={reportForm.summary} onChange={(v) => setReportForm({ ...reportForm, summary: v })} />
                    <Textarea label="Steps to Reproduce" value={reportForm.steps} onChange={(v) => setReportForm({ ...reportForm, steps: v })} />
                    <Textarea label="Impact" value={reportForm.impact} onChange={(v) => setReportForm({ ...reportForm, impact: v })} />
                    <Textarea label="Remediation" value={reportForm.remediation} onChange={(v) => setReportForm({ ...reportForm, remediation: v })} />
                    <div className="grid gap-3 md:grid-cols-2">
                      <Input label="CWE" value={reportForm.cwe} onChange={(v) => setReportForm({ ...reportForm, cwe: v })} />
                      <Input label="CVSS" value={reportForm.cvss} onChange={(v) => setReportForm({ ...reportForm, cvss: v })} />
                    </div>
                    <PrimaryButton onClick={addReport} label="Save Report" />
                  </div>
                </Panel>
                <Panel title="Report Preview">
                  <pre className="whitespace-pre-wrap rounded-lg border border-[#2e2e2e] bg-[#161616] p-4 font-mono text-xs leading-relaxed text-[#6b7280]">
                    {generateReportPreview()}
                  </pre>
                  <div className="mt-5 space-y-2">
                    {(selectedProgram.reports ?? []).map((report) => (
                      <div key={report.id} className="flex items-start justify-between gap-3 rounded-xl border border-[#2e2e2e] bg-[#161616] px-4 py-3">
                        <div>
                          <div className="font-semibold text-[#f1f5f9]">{report.title}</div>
                          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                            <StatusBadge status={report.status} />
                            {report.cwe && <span className="font-mono text-xs text-[#52525b]">CWE: {report.cwe}</span>}
                            {report.cvss && <span className="font-mono text-xs text-[#52525b]">CVSS: {report.cvss}</span>}
                          </div>
                        </div>
                        <DangerButton onClick={() => deleteReport(report.id)} label="Delete" small />
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Shared UI primitives
// ---------------------------------------------------------------------------

function DashboardCard({ title, value, accent }: { title: string; value: number; accent: string }) {
  return (
    <div className="rounded-xl border border-[#2e2e2e] bg-[#1a1a1a] p-5 transition hover:border-[#3a3a3a]">
      <div className="text-[9px] font-semibold uppercase tracking-widest text-[#52525b]">{title}</div>
      <div className="mt-3 font-mono text-4xl font-bold tracking-tight" style={{ color: accent }}>{value}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-[#2e2e2e] bg-[#1a1a1a] p-5">
      <h3 className="mb-5 text-[10px] font-semibold uppercase tracking-widest text-[#52525b]">{title}</h3>
      {children}
    </div>
  );
}

function SectionHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="border-b border-[#2e2e2e] pb-5">
      <h2 className="text-2xl font-bold tracking-tight text-[#f1f5f9]">{title}</h2>
      <p className="mt-1.5 text-sm text-[#52525b]">{description}</p>
    </div>
  );
}

function Input({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <div>
      <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-[#52525b]">{label}</label>
      <input
        className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-3 py-2 text-sm text-[#f1f5f9] placeholder-[#3a3a3a] transition focus:border-[#f59e0b] focus:outline-none"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function Textarea({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  const [mode, setMode] = useState<"edit" | "preview">("edit");
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between">
        <label className="text-[10px] font-semibold uppercase tracking-widest text-[#52525b]">{label}</label>
        <div className="flex rounded border border-[#2e2e2e] bg-[#161616] p-0.5">
          {(["edit", "preview"] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className={`rounded px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider transition ${mode === m ? "bg-[#2e2e2e] text-[#f1f5f9]" : "text-[#52525b] hover:text-[#6b7280]"}`}>
              {m}
            </button>
          ))}
        </div>
      </div>
      {mode === "edit" && (
        <textarea rows={4} placeholder="Supports markdown…"
          className="w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-3 py-2 font-mono text-sm text-[#f1f5f9] placeholder-[#3a3a3a] transition focus:border-[#f59e0b] focus:outline-none"
          value={value} onChange={(e) => onChange(e.target.value)} />
      )}
      {mode === "preview" && (
        <div className="min-h-[104px] w-full rounded-md border border-[#2e2e2e] bg-[#161616] px-3 py-2">
          {value.trim() ? (
            <div className="text-sm text-[#6b7280] leading-relaxed space-y-2
              [&_h1]:text-lg [&_h1]:font-semibold [&_h1]:text-[#f1f5f9]
              [&_h2]:text-base [&_h2]:font-semibold [&_h2]:text-[#f1f5f9]
              [&_h3]:text-sm [&_h3]:font-semibold [&_h3]:text-[#94a3b8]
              [&_strong]:text-[#f1f5f9]
              [&_a]:text-[#89b4fa] [&_a]:no-underline hover:[&_a]:underline
              [&_code]:rounded [&_code]:bg-[#2e2e2e] [&_code]:px-1 [&_code]:py-0.5 [&_code]:text-xs [&_code]:text-[#a6e3a1] [&_code]:font-mono
              [&_pre]:rounded-md [&_pre]:border [&_pre]:border-[#2e2e2e] [&_pre]:bg-[#161616] [&_pre]:p-3 [&_pre]:text-xs
              [&_ul]:list-disc [&_ul]:pl-4 [&_ol]:list-decimal [&_ol]:pl-4
              [&_li]:text-[#6b7280]
              [&_blockquote]:border-l-2 [&_blockquote]:border-[#f59e0b]/30 [&_blockquote]:pl-3 [&_blockquote]:text-[#52525b]
              [&_hr]:border-[#2e2e2e]">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{value}</ReactMarkdown>
            </div>
          ) : (
            <p className="text-xs text-[#3a3a3a] italic">Nothing to preview.</p>
          )}
        </div>
      )}
    </div>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="mb-4 last:mb-0">
      <div className="text-[9px] font-semibold uppercase tracking-widest text-[#52525b]">{label}</div>
      <div className="mt-1 text-sm text-[#94a3b8]">{value}</div>
    </div>
  );
}

function ListCard({ title, subtitle, onDelete }: { title: string; subtitle: string; onDelete: () => void }) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-[#2e2e2e] bg-[#161616] px-4 py-3">
      <div className="min-w-0">
        <div className="truncate text-sm font-medium text-[#f1f5f9]">{title}</div>
        <div className="mt-0.5 truncate text-xs text-[#52525b]">{subtitle}</div>
      </div>
      <DangerButton onClick={onDelete} label="Delete" small />
    </div>
  );
}

function PrimaryButton({ onClick, label }: { onClick: () => void; label: string }) {
  return (
    <button onClick={onClick} className="rounded-md bg-[#f59e0b] px-4 py-2 text-sm font-semibold text-[#161616] transition hover:bg-[#fbbf24] active:scale-[0.98]">
      {label}
    </button>
  );
}

function DangerButton({ onClick, label, small }: { onClick: () => void; label: string; small?: boolean }) {
  return (
    <button onClick={onClick} className={`flex-shrink-0 rounded-md border border-red-900/50 bg-red-950/30 font-semibold text-red-400 transition hover:bg-red-950/60 hover:text-red-300 active:scale-[0.98] ${small ? "px-2.5 py-1 text-xs" : "px-4 py-2 text-sm"}`}>
      {label}
    </button>
  );
}
