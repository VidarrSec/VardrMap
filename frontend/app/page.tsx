"use client";

import { useEffect, useMemo, useState } from "react";
import { signIn, signOut } from "next-auth/react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ScopeItem = {
  id: string;
  value: string;
  kind: string;
  notes: string;
};

type ImportRecord = {
  id: string;
  tool_type: string;
  filename: string;
  imported_count: number;
};

type ReconItem = {
  id: string;
  source: string;
  url?: string;
  path?: string;
  host?: string;
  title?: string;
  status_code?: number;
  webserver?: string;
  port?: string | number;
  tech?: string[];
  length?: number;
  words?: number;
  lines?: number;
  content_type?: string;
  notes?: string;
};

type ScanItem = {
  id: string;
  source: string;
  template_id: string;
  title: string;
  severity: string;
  asset: string;
  matched_at?: string;
  type?: string;
  description?: string;
  status: string;
};

type ManualTest = {
  id: string;
  title: string;
  hypothesis: string;
  payload: string;
  evidence: string;
  status: string;
};

type Finding = {
  id: string;
  title: string;
  severity: string;
  asset: string;
  status: string;
  summary: string;
  steps: string;
  impact: string;
  remediation: string;
};

type Report = {
  id: string;
  finding_id: string;
  title: string;
  summary: string;
  steps: string;
  impact: string;
  remediation: string;
  cwe: string;
  cvss: string;
  status: string;
};

type Program = {
  id: string;
  name: string;
  platform: string;
  program_url: string;
  scope_summary: string;
  severity_guidance: string;
  safe_harbor_notes: string;
  scope: {
    in: ScopeItem[];
    out: ScopeItem[];
  };
  imports: ImportRecord[];
  recon: ReconItem[];
  scans: ScanItem[];
  manual_tests: ManualTest[];
  findings: Finding[];
  reports: Report[];
};

type Section =
  | "dashboard"
  | "program"
  | "scope"
  | "imports"
  | "recon"
  | "scanning"
  | "manual"
  | "findings"
  | "reports";

type AppSession = {
  user?: {
    name?: string | null;
    email?: string | null;
    image?: string | null;
    githubId?: string;
    username?: string;
  };
  backendToken?: string;
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

const EMPTY_PROGRAM: Program = {
  id: "",
  name: "",
  platform: "",
  program_url: "",
  scope_summary: "",
  severity_guidance: "",
  safe_harbor_notes: "",
  scope: { in: [], out: [] },
  imports: [],
  recon: [],
  scans: [],
  manual_tests: [],
  findings: [],
  reports: [],
};

// ---------------------------------------------------------------------------
// Severity badge helper
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase();
  const color =
    s === "critical"
      ? "bg-red-950 text-red-400 border-red-800"
      : s === "high"
      ? "bg-orange-950 text-orange-400 border-orange-800"
      : s === "medium"
      ? "bg-yellow-950 text-yellow-400 border-yellow-800"
      : s === "low"
      ? "bg-blue-950 text-blue-400 border-blue-800"
      : "bg-zinc-900 text-zinc-400 border-zinc-700";

  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider ${color}`}
    >
      {severity || "info"}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const s = status?.toLowerCase();
  const color =
    s === "new"
      ? "bg-zinc-900 text-zinc-300 border-zinc-700"
      : s === "in_progress" || s === "triaged"
      ? "bg-blue-950 text-blue-300 border-blue-800"
      : s === "validated" || s === "accepted"
      ? "bg-emerald-950 text-emerald-400 border-emerald-800"
      : s === "closed" || s === "resolved"
      ? "bg-zinc-900 text-zinc-500 border-zinc-800"
      : s === "draft"
      ? "bg-zinc-900 text-zinc-400 border-zinc-700"
      : "bg-zinc-900 text-zinc-400 border-zinc-700";

  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider ${color}`}
    >
      {status || "—"}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Normalizer
// ---------------------------------------------------------------------------

function normalizeProgram(raw: any): Program {
  return {
    id: String(raw?.id ?? ""),
    name: String(raw?.name ?? ""),
    platform: String(raw?.platform ?? ""),
    program_url: String(raw?.program_url ?? ""),
    scope_summary: String(raw?.scope_summary ?? ""),
    severity_guidance: String(raw?.severity_guidance ?? ""),
    safe_harbor_notes: String(raw?.safe_harbor_notes ?? ""),
    scope: {
      in: Array.isArray(raw?.scope?.in) ? raw.scope.in : [],
      out: Array.isArray(raw?.scope?.out) ? raw.scope.out : [],
    },
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
    const res = await fetch("/api/auth/session", {
      method: "GET",
      credentials: "include",
      cache: "no-store",
    });
    if (!res.ok) return null;
    const session = await res.json();
    if (!session || Object.keys(session).length === 0) return null;
    return session;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function Home() {
  console.log("VardrMap page version: authfetch-live-check-1");

  const [session, setSession] = useState<AppSession | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  const [programs, setPrograms] = useState<Program[]>([]);
  const [selectedProgramId, setSelectedProgramId] = useState<string>("");
  const [activeSection, setActiveSection] = useState<Section>("dashboard");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const [newProgram, setNewProgram] = useState({
    name: "",
    platform: "",
    program_url: "",
    scope_summary: "",
    severity_guidance: "",
    safe_harbor_notes: "",
  });

  const [programForm, setProgramForm] = useState({
    name: "",
    platform: "",
    program_url: "",
    scope_summary: "",
    severity_guidance: "",
    safe_harbor_notes: "",
  });

  const [scopeIn, setScopeIn] = useState({ value: "", kind: "domain", notes: "" });
  const [scopeOut, setScopeOut] = useState({ value: "", kind: "domain", notes: "" });

  const [toolType, setToolType] = useState("ffuf");
  const [importFile, setImportFile] = useState<File | null>(null);

  const [manualTest, setManualTest] = useState({
    title: "",
    hypothesis: "",
    payload: "",
    evidence: "",
    status: "new",
  });

  const [findingForm, setFindingForm] = useState({
    title: "",
    severity: "medium",
    asset: "",
    status: "new",
    summary: "",
    steps: "",
    impact: "",
    remediation: "",
  });

  const [reportForm, setReportForm] = useState({
    finding_id: "",
    title: "",
    summary: "",
    steps: "",
    impact: "",
    remediation: "",
    cwe: "",
    cvss: "",
    status: "draft",
  });

  const selectedProgram = useMemo(
    () => programs.find((p) => p.id === selectedProgramId) || null,
    [programs, selectedProgramId]
  );

  const workflowCounts = useMemo(() => {
    const program = selectedProgram ?? EMPTY_PROGRAM;
    return {
      inScope: program.scope?.in?.length ?? 0,
      recon: program.recon?.length ?? 0,
      scans: program.scans?.length ?? 0,
      manual: program.manual_tests?.length ?? 0,
      findings: program.findings?.length ?? 0,
      reports: program.reports?.length ?? 0,
    };
  }, [selectedProgram]);

  useEffect(() => { void bootstrapSession(); }, []);

  useEffect(() => {
    if (!authLoading && session?.backendToken) void loadPrograms();
  }, [authLoading, session?.backendToken]);

  useEffect(() => {
    if (selectedProgram) {
      setProgramForm({
        name: selectedProgram.name || "",
        platform: selectedProgram.platform || "",
        program_url: selectedProgram.program_url || "",
        scope_summary: selectedProgram.scope_summary || "",
        severity_guidance: selectedProgram.severity_guidance || "",
        safe_harbor_notes: selectedProgram.safe_harbor_notes || "",
      });
    }
  }, [selectedProgram]);

  // -------------------------------------------------------------------------
  // Auth
  // -------------------------------------------------------------------------

  async function bootstrapSession() {
    setAuthLoading(true);
    const currentSession = await getFrontendSession();
    setSession(currentSession);
    setAuthLoading(false);
  }

  async function authFetch(path: string, init: RequestInit = {}) {
    const currentSession = session ?? (await getFrontendSession());
    if (!currentSession?.backendToken) throw new Error("Not authenticated");

    const headers = new Headers(init.headers || {});
    headers.set("Authorization", `Bearer ${currentSession.backendToken}`);
    if (!(init.body instanceof FormData) && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    const response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers,
      cache: "no-store",
    });

    if (response.status === 401) {
      setMessage("Your session is not authorized. Please sign in again.");
      throw new Error("Unauthorized");
    }

    return response;
  }

  // -------------------------------------------------------------------------
  // Programs
  // -------------------------------------------------------------------------

  async function loadPrograms() {
    try {
      setMessage("");
      const res = await authFetch("/programs");
      if (!res.ok) throw new Error(`Failed to load programs: ${res.status}`);
      const data = await res.json();
      const normalizedPrograms = Array.isArray(data?.programs)
        ? data.programs.map(normalizeProgram)
        : [];
      setPrograms(normalizedPrograms);
      if (!selectedProgramId && normalizedPrograms.length > 0) {
        setSelectedProgramId(normalizedPrograms[0].id);
      }
      if (normalizedPrograms.length === 0) setSelectedProgramId("");
    } catch (error) {
      console.error(error);
      setPrograms([]);
      setMessage("Failed to load programs.");
    }
  }

  async function refreshSelectedProgram(programId?: string) {
    const id = programId || selectedProgramId;
    if (!id) return;
    try {
      const res = await authFetch(`/programs/${id}`);
      if (!res.ok) throw new Error(`Failed to load program: ${res.status}`);
      const data = normalizeProgram(await res.json());
      setPrograms((prev) => {
        const exists = prev.some((p) => p.id === id);
        if (!exists) return [...prev, data];
        return prev.map((p) => (p.id === id ? data : p));
      });
    } catch (error) {
      console.error(error);
      setMessage("Failed to refresh selected program.");
    }
  }

  async function createProgram() {
    if (!newProgram.name.trim()) return;
    setLoading(true);
    setMessage("");
    try {
      const res = await authFetch("/programs", {
        method: "POST",
        body: JSON.stringify(newProgram),
      });
      if (!res.ok) throw new Error(`Failed to create program: ${res.status}`);
      const created = normalizeProgram(await res.json());
      setPrograms([...programs, created]);
      setSelectedProgramId(created.id);
      setNewProgram({ name: "", platform: "", program_url: "", scope_summary: "", severity_guidance: "", safe_harbor_notes: "" });
      setMessage("Program created.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to create program.");
    } finally {
      setLoading(false);
    }
  }

  async function saveProgramProfile() {
    if (!selectedProgramId) return;
    setLoading(true);
    setMessage("");
    try {
      const res = await authFetch(`/programs/${selectedProgramId}`, {
        method: "PATCH",
        body: JSON.stringify(programForm),
      });
      if (!res.ok) throw new Error(`Failed to save program: ${res.status}`);
      await refreshSelectedProgram();
      setMessage("Program profile saved.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to save program profile.");
    } finally {
      setLoading(false);
    }
  }

  async function deleteProgram() {
    if (!selectedProgramId) return;
    if (!confirm("Delete this program?")) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`Failed to delete program: ${res.status}`);
      const remaining = programs.filter((p) => p.id !== selectedProgramId);
      setPrograms(remaining);
      setSelectedProgramId(remaining[0]?.id || "");
      setMessage("Program deleted.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to delete program.");
    }
  }

  // -------------------------------------------------------------------------
  // Scope
  // -------------------------------------------------------------------------

  async function addScopeItem(scopeType: "in" | "out") {
    if (!selectedProgramId) return;
    const payload = scopeType === "in" ? scopeIn : scopeOut;
    if (!payload.value.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/scope/${scopeType}`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`Failed to add scope item: ${res.status}`);
      if (scopeType === "in") setScopeIn({ value: "", kind: "domain", notes: "" });
      else setScopeOut({ value: "", kind: "domain", notes: "" });
      await refreshSelectedProgram();
      setMessage("Scope updated.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to add scope item.");
    }
  }

  async function deleteScopeItem(scopeType: "in" | "out", itemId: string) {
    if (!selectedProgramId) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/scope/${scopeType}/${itemId}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`Failed to delete scope item: ${res.status}`);
      await refreshSelectedProgram();
      setMessage("Scope item deleted.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to delete scope item.");
    }
  }

  // -------------------------------------------------------------------------
  // Imports
  // -------------------------------------------------------------------------

  async function handleImport() {
    if (!selectedProgramId || !importFile) return;
    const formData = new FormData();
    formData.append("tool_type", toolType);
    formData.append("file", importFile);
    setLoading(true);
    setMessage("");
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/imports`, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) throw new Error(`Failed to import: ${res.status}`);
      setImportFile(null);
      await refreshSelectedProgram();
      setMessage("Import complete.");
    } catch (error) {
      console.error(error);
      setMessage("Import failed.");
    } finally {
      setLoading(false);
    }
  }

  // -------------------------------------------------------------------------
  // Manual tests
  // -------------------------------------------------------------------------

  async function addManualTest() {
    if (!selectedProgramId || !manualTest.title.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/manual-tests`, {
        method: "POST",
        body: JSON.stringify(manualTest),
      });
      if (!res.ok) throw new Error(`Failed to add manual test: ${res.status}`);
      setManualTest({ title: "", hypothesis: "", payload: "", evidence: "", status: "new" });
      await refreshSelectedProgram();
      setMessage("Manual testing note added.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to add manual test.");
    }
  }

  async function deleteManualTest(testId: string) {
    if (!selectedProgramId) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/manual-tests/${testId}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`Failed to delete manual test: ${res.status}`);
      await refreshSelectedProgram();
      setMessage("Manual test deleted.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to delete manual test.");
    }
  }

  // -------------------------------------------------------------------------
  // Findings
  // -------------------------------------------------------------------------

  async function addFinding() {
    if (!selectedProgramId || !findingForm.title.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/findings`, {
        method: "POST",
        body: JSON.stringify(findingForm),
      });
      if (!res.ok) throw new Error(`Failed to add finding: ${res.status}`);
      setFindingForm({ title: "", severity: "medium", asset: "", status: "new", summary: "", steps: "", impact: "", remediation: "" });
      await refreshSelectedProgram();
      setMessage("Finding added.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to add finding.");
    }
  }

  async function deleteFinding(findingId: string) {
    if (!selectedProgramId) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/findings/${findingId}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`Failed to delete finding: ${res.status}`);
      await refreshSelectedProgram();
      setMessage("Finding deleted.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to delete finding.");
    }
  }

  // -------------------------------------------------------------------------
  // Reports
  // -------------------------------------------------------------------------

  async function addReport() {
    if (!selectedProgramId || !reportForm.title.trim()) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/reports`, {
        method: "POST",
        body: JSON.stringify(reportForm),
      });
      if (!res.ok) throw new Error(`Failed to save report: ${res.status}`);
      setReportForm({ finding_id: "", title: "", summary: "", steps: "", impact: "", remediation: "", cwe: "", cvss: "", status: "draft" });
      await refreshSelectedProgram();
      setMessage("Report saved.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to save report.");
    }
  }

  async function deleteReport(reportId: string) {
    if (!selectedProgramId) return;
    try {
      const res = await authFetch(`/programs/${selectedProgramId}/reports/${reportId}`, { method: "DELETE" });
      if (!res.ok) throw new Error(`Failed to delete report: ${res.status}`);
      await refreshSelectedProgram();
      setMessage("Report deleted.");
    } catch (error) {
      console.error(error);
      setMessage("Failed to delete report.");
    }
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  function promoteScanToFinding(scan: ScanItem) {
    setActiveSection("findings");
    setFindingForm({
      title: scan.title,
      severity: scan.severity || "medium",
      asset: scan.asset || "",
      status: "candidate",
      summary: scan.description || "",
      steps: "",
      impact: "",
      remediation: "",
    });
  }

  function generateReportPreview() {
    return `# ${reportForm.title || "Untitled Report"}

## Summary
${reportForm.summary || ""}

## Steps to Reproduce
${reportForm.steps || ""}

## Impact
${reportForm.impact || ""}

## Remediation
${reportForm.remediation || ""}

## CWE
${reportForm.cwe || ""}

## CVSS
${reportForm.cvss || ""}
`;
  }

  const isErrorMessage = message.toLowerCase().includes("fail") || message.toLowerCase().includes("error") || message.toLowerCase().includes("not authorized");

  // -------------------------------------------------------------------------
  // Sidebar nav button
  // -------------------------------------------------------------------------

  const SidebarButton = ({ section, label }: { section: Section; label: string }) => (
    <button
      onClick={() => setActiveSection(section)}
      className={`group relative w-full rounded-md px-3 py-2 text-left text-sm font-medium transition-all duration-150 ${
        activeSection === section
          ? "bg-zinc-800 text-white"
          : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"
      }`}
    >
      {activeSection === section && (
        <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-white" />
      )}
      <span className="pl-2">{label}</span>
    </button>
  );

  // -------------------------------------------------------------------------
  // Loading / login screens
  // -------------------------------------------------------------------------

  if (authLoading) {
    return (
      <main className="min-h-screen bg-[#0a0a0a] text-white">
        <div className="flex min-h-screen items-center justify-center">
          <div className="flex items-center gap-3 text-zinc-500">
            <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-zinc-500" />
            <span className="text-sm tracking-wide">Loading session…</span>
          </div>
        </div>
      </main>
    );
  }

  if (!session?.backendToken) {
    return (
      <main className="min-h-screen bg-[#0a0a0a] text-white">
        <div className="flex min-h-screen items-center justify-center p-6">
          <div className="w-full max-w-sm rounded-2xl border border-zinc-800 bg-zinc-950 p-10 text-center shadow-2xl">
            <div className="mx-auto mb-5 flex h-10 w-10 items-center justify-center rounded-xl bg-zinc-800">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-zinc-300"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            </div>
            <h1 className="text-2xl font-bold tracking-tight">VardrMap</h1>
            <p className="mt-2 text-sm text-zinc-500">
              Sign in with GitHub to access your private bug bounty workspace.
            </p>
            <button
              onClick={() => signIn("github")}
              className="mt-7 w-full rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition hover:bg-zinc-100 active:scale-[0.98]"
            >
              Sign in with GitHub
            </button>
          </div>
        </div>
      </main>
    );
  }

  // -------------------------------------------------------------------------
  // App shell
  // -------------------------------------------------------------------------

  return (
    <main className="min-h-screen bg-[#0a0a0a] text-white">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[260px_1fr]">

        {/* Sidebar */}
        <aside className="flex flex-col border-r border-zinc-800/60 bg-[#0d0d0d]">
          {/* Brand */}
          <div className="border-b border-zinc-800/60 px-5 py-5">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xl font-bold tracking-tight">VardrMap</span>
                  <span className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-[10px] text-zinc-500">BETA</span>
                </div>
                <p className="mt-1 text-xs text-zinc-600">Bug bounty workflow workspace</p>
              </div>
              <button
                onClick={() => signOut({ callbackUrl: "/" })}
                className="rounded-md border border-zinc-800 px-2.5 py-1.5 text-xs text-zinc-500 transition hover:border-zinc-700 hover:text-zinc-300"
              >
                Sign out
              </button>
            </div>
            <p className="mt-3 truncate text-xs text-zinc-600">
              {session.user?.username || session.user?.email || "GitHub user"}
            </p>
          </div>

          {/* Program selector */}
          <div className="border-b border-zinc-800/60 px-5 py-4">
            <label className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
              Active Program
            </label>
            <select
              className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-2 text-sm text-zinc-200 transition focus:border-zinc-600 focus:outline-none"
              value={selectedProgramId}
              onChange={(e) => setSelectedProgramId(e.target.value)}
            >
              <option value="">Choose a program</option>
              {programs.map((program) => (
                <option key={program.id} value={program.id}>
                  {program.name}
                </option>
              ))}
            </select>
          </div>

          {/* Nav */}
          <nav className="flex-1 space-y-0.5 px-3 py-4">
            <SidebarButton section="dashboard" label="Dashboard" />
            <SidebarButton section="program" label="Program Profile" />
            <SidebarButton section="scope" label="Scope" />
            <SidebarButton section="imports" label="Imports" />
            <SidebarButton section="recon" label="Recon" />
            <SidebarButton section="scanning" label="Scanning" />
            <SidebarButton section="manual" label="Manual Testing" />
            <SidebarButton section="findings" label="Findings" />
            <SidebarButton section="reports" label="Reports" />
          </nav>

          {/* Create program */}
          <div className="border-t border-zinc-800/60 px-5 py-5">
            <p className="mb-3 text-[10px] font-semibold uppercase tracking-widest text-zinc-600">
              New Program
            </p>
            <div className="space-y-2">
              <input
                className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-2 text-sm text-zinc-200 placeholder-zinc-700 transition focus:border-zinc-600 focus:outline-none"
                placeholder="Program name"
                value={newProgram.name}
                onChange={(e) => setNewProgram({ ...newProgram, name: e.target.value })}
              />
              <input
                className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-2 text-sm text-zinc-200 placeholder-zinc-700 transition focus:border-zinc-600 focus:outline-none"
                placeholder="Platform"
                value={newProgram.platform}
                onChange={(e) => setNewProgram({ ...newProgram, platform: e.target.value })}
              />
              <input
                className="w-full rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-2 text-sm text-zinc-200 placeholder-zinc-700 transition focus:border-zinc-600 focus:outline-none"
                placeholder="Program URL"
                value={newProgram.program_url}
                onChange={(e) => setNewProgram({ ...newProgram, program_url: e.target.value })}
              />
              <button
                onClick={createProgram}
                disabled={loading}
                className="w-full rounded-md bg-white px-4 py-2 text-sm font-semibold text-black transition hover:bg-zinc-100 active:scale-[0.98] disabled:opacity-50"
              >
                {loading ? "Working…" : "Create Program"}
              </button>
            </div>
          </div>
        </aside>

        {/* Main content */}
        <section className="min-w-0 overflow-auto p-6 lg:p-8">
          {/* Message banner */}
          {message && (
            <div
              className={`mb-5 flex items-center gap-2.5 rounded-lg border px-4 py-3 text-sm ${
                isErrorMessage
                  ? "border-red-900 bg-red-950/40 text-red-300"
                  : "border-emerald-900 bg-emerald-950/40 text-emerald-300"
              }`}
            >
              <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${isErrorMessage ? "bg-red-400" : "bg-emerald-400"}`} />
              {message}
            </div>
          )}

          {/* No program selected */}
          {!selectedProgram && (
            <div className="rounded-2xl border border-dashed border-zinc-800 p-14 text-center">
              <p className="text-sm text-zinc-600">Create or select a program to begin.</p>
            </div>
          )}

          {/* ----------------------------------------------------------------
              Dashboard
          ---------------------------------------------------------------- */}
          {selectedProgram && activeSection === "dashboard" && (
            <div className="space-y-7">
              <SectionHeader
                title={selectedProgram.name}
                description="Select a program, confirm scope, import tool output, review recon, validate findings, and draft a report."
              />

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <DashboardCard title="In-Scope Assets" value={workflowCounts.inScope} />
                <DashboardCard title="Recon Entries" value={workflowCounts.recon} />
                <DashboardCard title="Scan Results" value={workflowCounts.scans} />
                <DashboardCard title="Manual Tests" value={workflowCounts.manual} />
                <DashboardCard title="Findings" value={workflowCounts.findings} />
                <DashboardCard title="Reports" value={workflowCounts.reports} />
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
                    <p className="text-sm text-zinc-600">No imports yet.</p>
                  ) : (
                    <div className="space-y-2">
                      {selectedProgram.imports.map((item) => (
                        <div key={item.id} className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-3 text-sm">
                          <span className="font-mono text-xs font-semibold text-zinc-300 uppercase">{item.tool_type}</span>
                          <span className="text-zinc-500">{item.imported_count} records</span>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </div>
          )}

          {/* ----------------------------------------------------------------
              Program Profile
          ---------------------------------------------------------------- */}
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

          {/* ----------------------------------------------------------------
              Scope
          ---------------------------------------------------------------- */}
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

          {/* ----------------------------------------------------------------
              Imports
          ---------------------------------------------------------------- */}
          {selectedProgram && activeSection === "imports" && (
            <div className="space-y-7">
              <SectionHeader title="Imports" description="Upload tool output instead of manually typing recon data." />
              <Panel title="Import Tool Output">
                <div className="grid gap-4 md:grid-cols-3">
                  <div>
                    <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-zinc-500">Tool Type</label>
                    <select
                      className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-2 text-sm text-zinc-200 transition focus:border-zinc-600 focus:outline-none"
                      value={toolType}
                      onChange={(e) => setToolType(e.target.value)}
                    >
                      <option value="ffuf">ffuf</option>
                      <option value="httpx">httpx</option>
                      <option value="nuclei">nuclei</option>
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-zinc-500">JSON / JSONL File</label>
                    <input
                      type="file"
                      accept=".json,.jsonl,application/json,application/x-ndjson"
                      onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                      className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-2 text-sm text-zinc-400 file:mr-3 file:rounded file:border-0 file:bg-zinc-800 file:px-2.5 file:py-1 file:text-xs file:font-semibold file:text-zinc-300"
                    />
                  </div>
                </div>
                <div className="mt-5">
                  <PrimaryButton onClick={handleImport} label={loading ? "Importing…" : "Import Results"} />
                </div>
                <div className="mt-6 rounded-xl border border-zinc-800/60 bg-zinc-950 p-4">
                  <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-zinc-500">Supported imports</p>
                  <div className="space-y-1.5 text-sm text-zinc-500">
                    <p><span className="font-mono text-zinc-400">ffuf</span> — Recon endpoints and paths</p>
                    <p><span className="font-mono text-zinc-400">httpx</span> — Live hosts, titles, technologies</p>
                    <p><span className="font-mono text-zinc-400">nuclei</span> — Candidate scan findings</p>
                  </div>
                </div>
              </Panel>
            </div>
          )}

          {/* ----------------------------------------------------------------
              Recon
          ---------------------------------------------------------------- */}
          {selectedProgram && activeSection === "recon" && (
            <div className="space-y-7">
              <SectionHeader title="Recon" description="Review discovered subdomains, endpoints, paths, and technologies." />
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="Discovered Assets">
                  {(selectedProgram.recon ?? []).length === 0 ? (
                    <p className="text-sm text-zinc-600">No recon data imported yet.</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="min-w-full text-sm">
                        <thead>
                          <tr className="border-b border-zinc-800 text-left">
                            <th className="pb-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wider text-zinc-600">Source</th>
                            <th className="pb-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wider text-zinc-600">URL / Host</th>
                            <th className="pb-2.5 pr-4 text-[10px] font-semibold uppercase tracking-wider text-zinc-600">Path / Title</th>
                            <th className="pb-2.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-600">Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(selectedProgram.recon ?? []).map((item, i) => (
                            <tr key={item.id} className={`border-b border-zinc-900 text-xs ${i % 2 === 0 ? "" : "bg-zinc-950/40"}`}>
                              <td className="py-2.5 pr-4 font-mono text-zinc-500">{item.source}</td>
                              <td className="py-2.5 pr-4 max-w-[180px] truncate text-zinc-300">{item.url || item.host || "—"}</td>
                              <td className="py-2.5 pr-4 max-w-[160px] truncate text-zinc-400">{item.path || item.title || "—"}</td>
                              <td className="py-2.5">
                                {item.status_code ? (
                                  <span className="font-mono text-xs text-zinc-400">{item.status_code}</span>
                                ) : "—"}
                              </td>
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
                      <div key={item.id} className="rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-3 text-sm">
                        <div className="font-medium text-zinc-200">{item.url || item.host || "Unknown asset"}</div>
                        <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-zinc-500">
                          <span>Server: <span className="text-zinc-400">{item.webserver || "—"}</span></span>
                          <span>Tech: <span className="text-zinc-400">{Array.isArray(item.tech) ? item.tech.join(", ") || "—" : "—"}</span></span>
                          <span>L/W/Li: <span className="font-mono text-zinc-400">{item.length || 0}/{item.words || 0}/{item.lines || 0}</span></span>
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}

          {/* ----------------------------------------------------------------
              Scanning
          ---------------------------------------------------------------- */}
          {selectedProgram && activeSection === "scanning" && (
            <div className="space-y-7">
              <SectionHeader title="Scanning" description="Review candidate vulnerabilities from imported scan results." />
              <Panel title="Nuclei Candidates">
                {(selectedProgram.scans ?? []).length === 0 ? (
                  <p className="text-sm text-zinc-600">No scan results imported yet.</p>
                ) : (
                  <div className="space-y-3">
                    {(selectedProgram.scans ?? []).map((scan) => (
                      <div key={scan.id} className="rounded-xl border border-zinc-800 bg-zinc-950 p-4">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="font-semibold text-zinc-100">{scan.title}</div>
                            <div className="mt-1 font-mono text-xs text-zinc-500">
                              {scan.asset || "Unknown asset"} · {scan.template_id}
                            </div>
                          </div>
                          <div className="flex flex-shrink-0 items-center gap-2">
                            <SeverityBadge severity={scan.severity} />
                            <button
                              onClick={() => promoteScanToFinding(scan)}
                              className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 text-xs font-semibold text-zinc-200 transition hover:border-zinc-600 hover:bg-zinc-700"
                            >
                              Promote →
                            </button>
                          </div>
                        </div>
                        {scan.description && (
                          <p className="mt-3 text-sm text-zinc-400">{scan.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </div>
          )}

          {/* ----------------------------------------------------------------
              Manual Testing
          ---------------------------------------------------------------- */}
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
                    <p className="text-sm text-zinc-600">No manual tests saved yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {(selectedProgram.manual_tests ?? []).map((test) => (
                        <div key={test.id} className="rounded-xl border border-zinc-800 bg-zinc-950 p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="font-semibold text-zinc-100">{test.title}</div>
                              <div className="mt-1"><StatusBadge status={test.status} /></div>
                            </div>
                            <DangerButton onClick={() => deleteManualTest(test.id)} label="Delete" small />
                          </div>
                          {test.hypothesis && <p className="mt-3 text-sm text-zinc-400">{test.hypothesis}</p>}
                          {test.payload && <p className="mt-2 font-mono text-xs text-zinc-500">Payload: {test.payload}</p>}
                          {test.evidence && <p className="mt-1 text-xs text-zinc-500">Evidence: {test.evidence}</p>}
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </div>
          )}

          {/* ----------------------------------------------------------------
              Findings
          ---------------------------------------------------------------- */}
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
                    <p className="text-sm text-zinc-600">No findings yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {(selectedProgram.findings ?? []).map((finding) => (
                        <div key={finding.id} className="rounded-xl border border-zinc-800 bg-zinc-950 p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="font-semibold text-zinc-100">{finding.title}</div>
                              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                                <SeverityBadge severity={finding.severity} />
                                <StatusBadge status={finding.status} />
                                {finding.asset && (
                                  <span className="font-mono text-xs text-zinc-600">{finding.asset}</span>
                                )}
                              </div>
                            </div>
                            <DangerButton onClick={() => deleteFinding(finding.id)} label="Delete" small />
                          </div>
                          {finding.summary && <p className="mt-3 text-sm text-zinc-400">{finding.summary}</p>}
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </div>
          )}

          {/* ----------------------------------------------------------------
              Reports
          ---------------------------------------------------------------- */}
          {selectedProgram && activeSection === "reports" && (
            <div className="space-y-7">
              <SectionHeader title="Reports" description="Draft submission-ready reports from validated findings." />
              <div className="grid gap-5 xl:grid-cols-2">
                <Panel title="Draft Report">
                  <div className="grid gap-3">
                    <div>
                      <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-zinc-500">Link Finding</label>
                      <select
                        className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-2 text-sm text-zinc-200 transition focus:border-zinc-600 focus:outline-none"
                        value={reportForm.finding_id}
                        onChange={(e) => {
                          const findingId = e.target.value;
                          const finding = (selectedProgram.findings ?? []).find((f) => f.id === findingId);
                          setReportForm({
                            ...reportForm,
                            finding_id: findingId,
                            title: finding?.title || reportForm.title,
                            summary: finding?.summary || reportForm.summary,
                            steps: finding?.steps || reportForm.steps,
                            impact: finding?.impact || reportForm.impact,
                            remediation: finding?.remediation || reportForm.remediation,
                          });
                        }}
                      >
                        <option value="">No linked finding</option>
                        {(selectedProgram.findings ?? []).map((finding) => (
                          <option key={finding.id} value={finding.id}>
                            {finding.title}
                          </option>
                        ))}
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
                  <pre className="whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs leading-relaxed text-zinc-400">
                    {generateReportPreview()}
                  </pre>
                  <div className="mt-5 space-y-2">
                    {(selectedProgram.reports ?? []).map((report) => (
                      <div key={report.id} className="flex items-start justify-between gap-3 rounded-xl border border-zinc-800 bg-zinc-950 px-4 py-3">
                        <div>
                          <div className="font-semibold text-zinc-100">{report.title}</div>
                          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                            <StatusBadge status={report.status} />
                            {report.cwe && <span className="font-mono text-xs text-zinc-600">CWE: {report.cwe}</span>}
                            {report.cvss && <span className="font-mono text-xs text-zinc-600">CVSS: {report.cvss}</span>}
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
// Shared UI components
// ---------------------------------------------------------------------------

function DashboardCard({ title, value }: { title: string; value: number }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 transition hover:border-zinc-700">
      <div className="text-[11px] font-semibold uppercase tracking-widest text-zinc-600">{title}</div>
      <div className="mt-3 font-mono text-4xl font-bold tracking-tight text-zinc-100">{value}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-5">
      <h3 className="mb-5 text-sm font-semibold uppercase tracking-wider text-zinc-400">{title}</h3>
      {children}
    </div>
  );
}

function SectionHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="border-b border-zinc-800/60 pb-5">
      <h2 className="text-2xl font-bold tracking-tight text-zinc-100">{title}</h2>
      <p className="mt-1.5 text-sm text-zinc-500">{description}</p>
    </div>
  );
}

function Input({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <div>
      <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-zinc-500">{label}</label>
      <input
        className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-700 transition focus:border-zinc-600 focus:outline-none"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function Textarea({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <div>
      <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-zinc-500">{label}</label>
      <textarea
        rows={4}
        className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-200 placeholder-zinc-700 transition focus:border-zinc-600 focus:outline-none"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="mb-4 last:mb-0">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-zinc-600">{label}</div>
      <div className="mt-1 text-sm text-zinc-300">{value}</div>
    </div>
  );
}

function ListCard({ title, subtitle, onDelete }: { title: string; subtitle: string; onDelete: () => void }) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-3">
      <div className="min-w-0">
        <div className="truncate font-medium text-zinc-200">{title}</div>
        <div className="mt-0.5 truncate text-xs text-zinc-500">{subtitle}</div>
      </div>
      <DangerButton onClick={onDelete} label="Delete" small />
    </div>
  );
}

function PrimaryButton({ onClick, label }: { onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black transition hover:bg-zinc-100 active:scale-[0.98]"
    >
      {label}
    </button>
  );
}

function DangerButton({ onClick, label, small }: { onClick: () => void; label: string; small?: boolean }) {
  return (
    <button
      onClick={onClick}
      className={`flex-shrink-0 rounded-md border border-red-900 bg-red-950/60 font-semibold text-red-400 transition hover:bg-red-950 hover:text-red-300 active:scale-[0.98] ${small ? "px-2.5 py-1 text-xs" : "px-4 py-2 text-sm"}`}
    >
      {label}
    </button>
  );
}
