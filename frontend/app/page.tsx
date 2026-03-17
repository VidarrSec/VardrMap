"use client";

import { useEffect, useMemo, useState } from "react";

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

const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export default function Home() {
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
    if (!selectedProgram) {
      return {
        inScope: 0,
        recon: 0,
        scans: 0,
        manual: 0,
        findings: 0,
        reports: 0,
      };
    }

    return {
      inScope: selectedProgram.scope.in.length,
      recon: selectedProgram.recon.length,
      scans: selectedProgram.scans.length,
      manual: selectedProgram.manual_tests.length,
      findings: selectedProgram.findings.length,
      reports: selectedProgram.reports.length,
    };
  }, [selectedProgram]);

  useEffect(() => {
    loadPrograms();
  }, []);

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

  async function loadPrograms() {
    try {
      const res = await fetch(`${API_URL}/programs`);
      const data = await res.json();
      setPrograms(data.programs || []);
      if (!selectedProgramId && data.programs?.length) {
        setSelectedProgramId(data.programs[0].id);
      }
    } catch {
      setMessage("Failed to load programs.");
    }
  }

  async function refreshSelectedProgram(programId?: string) {
    const id = programId || selectedProgramId;
    if (!id) return;

    const res = await fetch(`${API_URL}/programs/${id}`);
    const data = await res.json();

    setPrograms((prev) =>
      prev.map((p) => (p.id === id ? data : p))
    );
  }

  async function createProgram() {
    if (!newProgram.name.trim()) return;

    setLoading(true);
    setMessage("");

    try {
      const res = await fetch(`${API_URL}/programs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newProgram),
      });

      const created = await res.json();
      const updatedPrograms = [...programs, created];
      setPrograms(updatedPrograms);
      setSelectedProgramId(created.id);
      setNewProgram({
        name: "",
        platform: "",
        program_url: "",
        scope_summary: "",
        severity_guidance: "",
        safe_harbor_notes: "",
      });
      setMessage("Program created.");
    } catch {
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
      await fetch(`${API_URL}/programs/${selectedProgramId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(programForm),
      });

      await refreshSelectedProgram();
      setMessage("Program profile saved.");
    } catch {
      setMessage("Failed to save program profile.");
    } finally {
      setLoading(false);
    }
  }

  async function deleteProgram() {
    if (!selectedProgramId) return;
    if (!confirm("Delete this program?")) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}`, {
        method: "DELETE",
      });

      const remaining = programs.filter((p) => p.id !== selectedProgramId);
      setPrograms(remaining);
      setSelectedProgramId(remaining[0]?.id || "");
      setMessage("Program deleted.");
    } catch {
      setMessage("Failed to delete program.");
    }
  }

  async function addScopeItem(scopeType: "in" | "out") {
    if (!selectedProgramId) return;

    const payload = scopeType === "in" ? scopeIn : scopeOut;
    if (!payload.value.trim()) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/scope/${scopeType}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (scopeType === "in") {
        setScopeIn({ value: "", kind: "domain", notes: "" });
      } else {
        setScopeOut({ value: "", kind: "domain", notes: "" });
      }

      await refreshSelectedProgram();
      setMessage("Scope updated.");
    } catch {
      setMessage("Failed to add scope item.");
    }
  }

  async function deleteScopeItem(scopeType: "in" | "out", itemId: string) {
    if (!selectedProgramId) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/scope/${scopeType}/${itemId}`, {
        method: "DELETE",
      });

      await refreshSelectedProgram();
      setMessage("Scope item deleted.");
    } catch {
      setMessage("Failed to delete scope item.");
    }
  }

  async function handleImport() {
    if (!selectedProgramId || !importFile) return;

    const formData = new FormData();
    formData.append("tool_type", toolType);
    formData.append("file", importFile);

    setLoading(true);
    setMessage("");

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/imports`, {
        method: "POST",
        body: formData,
      });

      setImportFile(null);
      await refreshSelectedProgram();
      setMessage("Import complete.");
    } catch {
      setMessage("Import failed.");
    } finally {
      setLoading(false);
    }
  }

  async function addManualTest() {
    if (!selectedProgramId || !manualTest.title.trim()) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/manual-tests`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(manualTest),
      });

      setManualTest({
        title: "",
        hypothesis: "",
        payload: "",
        evidence: "",
        status: "new",
      });

      await refreshSelectedProgram();
      setMessage("Manual testing note added.");
    } catch {
      setMessage("Failed to add manual test.");
    }
  }

  async function deleteManualTest(testId: string) {
    if (!selectedProgramId) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/manual-tests/${testId}`, {
        method: "DELETE",
      });

      await refreshSelectedProgram();
      setMessage("Manual test deleted.");
    } catch {
      setMessage("Failed to delete manual test.");
    }
  }

  async function addFinding() {
    if (!selectedProgramId || !findingForm.title.trim()) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/findings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(findingForm),
      });

      setFindingForm({
        title: "",
        severity: "medium",
        asset: "",
        status: "new",
        summary: "",
        steps: "",
        impact: "",
        remediation: "",
      });

      await refreshSelectedProgram();
      setMessage("Finding added.");
    } catch {
      setMessage("Failed to add finding.");
    }
  }

  async function deleteFinding(findingId: string) {
    if (!selectedProgramId) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/findings/${findingId}`, {
        method: "DELETE",
      });

      await refreshSelectedProgram();
      setMessage("Finding deleted.");
    } catch {
      setMessage("Failed to delete finding.");
    }
  }

  async function addReport() {
    if (!selectedProgramId || !reportForm.title.trim()) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reportForm),
      });

      setReportForm({
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

      await refreshSelectedProgram();
      setMessage("Report saved.");
    } catch {
      setMessage("Failed to save report.");
    }
  }

  async function deleteReport(reportId: string) {
    if (!selectedProgramId) return;

    try {
      await fetch(`${API_URL}/programs/${selectedProgramId}/reports/${reportId}`, {
        method: "DELETE",
      });

      await refreshSelectedProgram();
      setMessage("Report deleted.");
    } catch {
      setMessage("Failed to delete report.");
    }
  }

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

  const SidebarButton = ({
    section,
    label,
  }: {
    section: Section;
    label: string;
  }) => (
    <button
      onClick={() => setActiveSection(section)}
      className={`w-full rounded-lg px-3 py-2 text-left text-sm transition ${
        activeSection === section
          ? "bg-white text-black"
          : "bg-zinc-900 text-zinc-200 hover:bg-zinc-800"
      }`}
    >
      {label}
    </button>
  );

  return (
    <main className="min-h-screen bg-black text-white">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[280px_1fr]">
        <aside className="border-r border-zinc-800 p-4">
          <div className="mb-6">
            <h1 className="text-3xl font-bold">VardrMap</h1>
            <p className="mt-2 text-sm text-zinc-400">
              Beginner-friendly bug bounty workflow workspace
            </p>
          </div>

          <div className="mb-4 rounded-xl border border-zinc-800 bg-zinc-950 p-3">
            <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-zinc-400">
              Select Program
            </label>
            <select
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm"
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

          <div className="mb-6 space-y-2">
            <SidebarButton section="dashboard" label="Dashboard" />
            <SidebarButton section="program" label="Program Profile" />
            <SidebarButton section="scope" label="Scope" />
            <SidebarButton section="imports" label="Imports" />
            <SidebarButton section="recon" label="Recon" />
            <SidebarButton section="scanning" label="Scanning" />
            <SidebarButton section="manual" label="Manual Testing" />
            <SidebarButton section="findings" label="Findings" />
            <SidebarButton section="reports" label="Reports" />
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-3">
            <h2 className="mb-3 text-sm font-semibold">Create Program</h2>
            <div className="space-y-2">
              <input
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm"
                placeholder="Program name"
                value={newProgram.name}
                onChange={(e) =>
                  setNewProgram({ ...newProgram, name: e.target.value })
                }
              />
              <input
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm"
                placeholder="Platform"
                value={newProgram.platform}
                onChange={(e) =>
                  setNewProgram({ ...newProgram, platform: e.target.value })
                }
              />
              <input
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm"
                placeholder="Program URL"
                value={newProgram.program_url}
                onChange={(e) =>
                  setNewProgram({ ...newProgram, program_url: e.target.value })
                }
              />
              <button
                onClick={createProgram}
                className="w-full rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
              >
                {loading ? "Working..." : "Create Program"}
              </button>
            </div>
          </div>
        </aside>

        <section className="p-4 lg:p-8">
          {message ? (
            <div className="mb-4 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-3 text-sm text-zinc-200">
              {message}
            </div>
          ) : null}

          {!selectedProgram ? (
            <div className="rounded-2xl border border-dashed border-zinc-700 p-10 text-center text-zinc-400">
              Create or select a program to begin.
            </div>
          ) : null}

          {selectedProgram && activeSection === "dashboard" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-3xl font-bold">{selectedProgram.name}</h2>
                <p className="mt-2 text-zinc-400">
                  Beginner workflow: select a program, confirm scope, import tool output,
                  review recon, validate findings, and draft a report.
                </p>
              </div>

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                <DashboardCard title="In Scope Assets" value={workflowCounts.inScope} />
                <DashboardCard title="Recon Entries" value={workflowCounts.recon} />
                <DashboardCard title="Scan Results" value={workflowCounts.scans} />
                <DashboardCard title="Manual Tests" value={workflowCounts.manual} />
                <DashboardCard title="Findings" value={workflowCounts.findings} />
                <DashboardCard title="Reports" value={workflowCounts.reports} />
              </div>

              <div className="grid gap-4 xl:grid-cols-2">
                <Panel title="Program Snapshot">
                  <KeyValue label="Platform" value={selectedProgram.platform || "—"} />
                  <KeyValue label="Program URL" value={selectedProgram.program_url || "—"} />
                  <KeyValue label="Scope Summary" value={selectedProgram.scope_summary || "—"} />
                  <KeyValue
                    label="Severity Guidance"
                    value={selectedProgram.severity_guidance || "—"}
                  />
                  <KeyValue
                    label="Safe Harbor"
                    value={selectedProgram.safe_harbor_notes || "—"}
                  />
                </Panel>

                <Panel title="Imports Summary">
                  {selectedProgram.imports.length === 0 ? (
                    <p className="text-sm text-zinc-400">No imports yet.</p>
                  ) : (
                    <div className="space-y-3">
                      {selectedProgram.imports.map((item) => (
                        <div
                          key={item.id}
                          className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-sm"
                        >
                          <div className="font-semibold">
                            {item.tool_type.toUpperCase()} — {item.filename}
                          </div>
                          <div className="text-zinc-400">
                            Imported: {item.imported_count}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </div>
          )}

          {selectedProgram && activeSection === "program" && (
            <div className="space-y-6">
              <SectionHeader
                title="Program Profile"
                description="Track target program details, policies, and notes."
              />

              <Panel title="Edit Program">
                <div className="grid gap-4 md:grid-cols-2">
                  <Input
                    label="Program Name"
                    value={programForm.name}
                    onChange={(v) => setProgramForm({ ...programForm, name: v })}
                  />
                  <Input
                    label="Platform"
                    value={programForm.platform}
                    onChange={(v) => setProgramForm({ ...programForm, platform: v })}
                  />
                  <Input
                    label="Program URL"
                    value={programForm.program_url}
                    onChange={(v) => setProgramForm({ ...programForm, program_url: v })}
                  />
                  <Input
                    label="Severity Guidance"
                    value={programForm.severity_guidance}
                    onChange={(v) =>
                      setProgramForm({ ...programForm, severity_guidance: v })
                    }
                  />
                </div>

                <div className="mt-4 grid gap-4">
                  <Textarea
                    label="Scope Summary"
                    value={programForm.scope_summary}
                    onChange={(v) =>
                      setProgramForm({ ...programForm, scope_summary: v })
                    }
                  />
                  <Textarea
                    label="Safe Harbor Notes"
                    value={programForm.safe_harbor_notes}
                    onChange={(v) =>
                      setProgramForm({ ...programForm, safe_harbor_notes: v })
                    }
                  />
                </div>

                <div className="mt-4 flex gap-3">
                  <button
                    onClick={saveProgramProfile}
                    className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
                  >
                    Save Profile
                  </button>
                  <button
                    onClick={deleteProgram}
                    className="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white"
                  >
                    Delete Program
                  </button>
                </div>
              </Panel>
            </div>
          )}

          {selectedProgram && activeSection === "scope" && (
            <div className="space-y-6">
              <SectionHeader
                title="Scope"
                description="Keep clear in-scope and out-of-scope boundaries before testing."
              />

              <div className="grid gap-6 xl:grid-cols-2">
                <Panel title="Add In-Scope Asset">
                  <div className="grid gap-3">
                    <Input
                      label="Value"
                      value={scopeIn.value}
                      onChange={(v) => setScopeIn({ ...scopeIn, value: v })}
                    />
                    <Input
                      label="Kind"
                      value={scopeIn.kind}
                      onChange={(v) => setScopeIn({ ...scopeIn, kind: v })}
                    />
                    <Textarea
                      label="Notes"
                      value={scopeIn.notes}
                      onChange={(v) => setScopeIn({ ...scopeIn, notes: v })}
                    />
                    <button
                      onClick={() => addScopeItem("in")}
                      className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
                    >
                      Add In-Scope Asset
                    </button>
                  </div>

                  <div className="mt-6 space-y-3">
                    {selectedProgram.scope.in.map((item) => (
                      <ListCard
                        key={item.id}
                        title={item.value}
                        subtitle={`${item.kind}${item.notes ? ` — ${item.notes}` : ""}`}
                        onDelete={() => deleteScopeItem("in", item.id)}
                      />
                    ))}
                  </div>
                </Panel>

                <Panel title="Add Out-of-Scope Asset">
                  <div className="grid gap-3">
                    <Input
                      label="Value"
                      value={scopeOut.value}
                      onChange={(v) => setScopeOut({ ...scopeOut, value: v })}
                    />
                    <Input
                      label="Kind"
                      value={scopeOut.kind}
                      onChange={(v) => setScopeOut({ ...scopeOut, kind: v })}
                    />
                    <Textarea
                      label="Notes"
                      value={scopeOut.notes}
                      onChange={(v) => setScopeOut({ ...scopeOut, notes: v })}
                    />
                    <button
                      onClick={() => addScopeItem("out")}
                      className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
                    >
                      Add Out-of-Scope Asset
                    </button>
                  </div>

                  <div className="mt-6 space-y-3">
                    {selectedProgram.scope.out.map((item) => (
                      <ListCard
                        key={item.id}
                        title={item.value}
                        subtitle={`${item.kind}${item.notes ? ` — ${item.notes}` : ""}`}
                        onDelete={() => deleteScopeItem("out", item.id)}
                      />
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}

          {selectedProgram && activeSection === "imports" && (
            <div className="space-y-6">
              <SectionHeader
                title="Imports"
                description="Upload tool output instead of manually typing recon data."
              />

              <Panel title="Import Tool Output">
                <div className="grid gap-4 md:grid-cols-3">
                  <div>
                    <label className="mb-2 block text-sm font-semibold">Tool Type</label>
                    <select
                      className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm"
                      value={toolType}
                      onChange={(e) => setToolType(e.target.value)}
                    >
                      <option value="ffuf">ffuf</option>
                      <option value="httpx">httpx</option>
                      <option value="nuclei">nuclei</option>
                    </select>
                  </div>

                  <div className="md:col-span-2">
                    <label className="mb-2 block text-sm font-semibold">JSON / JSONL File</label>
                    <input
                      type="file"
                      accept=".json,.jsonl,.txt"
                      onChange={(e) => setImportFile(e.target.files?.[0] || null)}
                      className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm"
                    />
                  </div>
                </div>

                <div className="mt-4 flex gap-3">
                  <button
                    onClick={handleImport}
                    className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
                  >
                    {loading ? "Importing..." : "Import Results"}
                  </button>
                </div>

                <div className="mt-6 rounded-xl border border-zinc-800 bg-zinc-950 p-4 text-sm text-zinc-300">
                  <p className="font-semibold">Supported beginner-friendly imports</p>
                  <ul className="mt-2 list-inside list-disc space-y-1 text-zinc-400">
                    <li>ffuf JSON → Recon endpoints and paths</li>
                    <li>httpx JSON/JSONL → Live hosts, titles, technologies</li>
                    <li>nuclei JSON/JSONL → Candidate scan findings</li>
                  </ul>
                </div>
              </Panel>
            </div>
          )}

          {selectedProgram && activeSection === "recon" && (
            <div className="space-y-6">
              <SectionHeader
                title="Recon"
                description="Review discovered subdomains, endpoints, paths, and technologies."
              />

              <div className="grid gap-6 xl:grid-cols-2">
                <Panel title="Discovered Assets">
                  <div className="overflow-x-auto">
                    <table className="min-w-full text-sm">
                      <thead className="border-b border-zinc-800 text-left text-zinc-400">
                        <tr>
                          <th className="py-2 pr-4">Source</th>
                          <th className="py-2 pr-4">URL / Host</th>
                          <th className="py-2 pr-4">Path / Title</th>
                          <th className="py-2 pr-4">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedProgram.recon.map((item) => (
                          <tr key={item.id} className="border-b border-zinc-900">
                            <td className="py-2 pr-4">{item.source}</td>
                            <td className="py-2 pr-4">{item.url || item.host || "—"}</td>
                            <td className="py-2 pr-4">{item.path || item.title || "—"}</td>
                            <td className="py-2 pr-4">{item.status_code || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <Panel title="Technology / Metadata">
                  <div className="space-y-3">
                    {selectedProgram.recon.map((item) => (
                      <div
                        key={item.id}
                        className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-sm"
                      >
                        <div className="font-semibold">{item.url || item.host || "Unknown asset"}</div>
                        <div className="mt-1 text-zinc-400">
                          Webserver: {item.webserver || "—"}
                        </div>
                        <div className="text-zinc-400">
                          Tech: {Array.isArray(item.tech) ? item.tech.join(", ") || "—" : "—"}
                        </div>
                        <div className="text-zinc-400">
                          Length/Words/Lines: {item.length || 0} / {item.words || 0} / {item.lines || 0}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}

          {selectedProgram && activeSection === "scanning" && (
            <div className="space-y-6">
              <SectionHeader
                title="Scanning"
                description="Review candidate vulnerabilities from imported scan results."
              />

              <Panel title="Nuclei Candidates">
                <div className="space-y-3">
                  {selectedProgram.scans.length === 0 ? (
                    <p className="text-sm text-zinc-400">No scan results imported yet.</p>
                  ) : (
                    selectedProgram.scans.map((scan) => (
                      <div
                        key={scan.id}
                        className="rounded-lg border border-zinc-800 bg-zinc-950 p-4"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <div className="text-lg font-semibold">{scan.title}</div>
                            <div className="text-sm text-zinc-400">
                              {scan.asset || "Unknown asset"} • {scan.template_id}
                            </div>
                          </div>
                          <div className="flex gap-2">
                            <span className="rounded-full bg-zinc-800 px-3 py-1 text-xs uppercase">
                              {scan.severity}
                            </span>
                            <button
                              onClick={() => promoteScanToFinding(scan)}
                              className="rounded-md bg-white px-3 py-1 text-sm font-semibold text-black"
                            >
                              Promote to Finding
                            </button>
                          </div>
                        </div>

                        <p className="mt-3 text-sm text-zinc-300">
                          {scan.description || "No description provided."}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              </Panel>
            </div>
          )}

          {selectedProgram && activeSection === "manual" && (
            <div className="space-y-6">
              <SectionHeader
                title="Manual Testing"
                description="Track hypotheses, payloads, exploitation notes, and evidence."
              />

              <div className="grid gap-6 xl:grid-cols-2">
                <Panel title="Add Manual Test Note">
                  <div className="grid gap-3">
                    <Input
                      label="Title"
                      value={manualTest.title}
                      onChange={(v) => setManualTest({ ...manualTest, title: v })}
                    />
                    <Textarea
                      label="Hypothesis"
                      value={manualTest.hypothesis}
                      onChange={(v) => setManualTest({ ...manualTest, hypothesis: v })}
                    />
                    <Textarea
                      label="Payload / Request Notes"
                      value={manualTest.payload}
                      onChange={(v) => setManualTest({ ...manualTest, payload: v })}
                    />
                    <Textarea
                      label="Evidence"
                      value={manualTest.evidence}
                      onChange={(v) => setManualTest({ ...manualTest, evidence: v })}
                    />
                    <Input
                      label="Status"
                      value={manualTest.status}
                      onChange={(v) => setManualTest({ ...manualTest, status: v })}
                    />
                    <button
                      onClick={addManualTest}
                      className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
                    >
                      Save Manual Test
                    </button>
                  </div>
                </Panel>

                <Panel title="Saved Manual Tests">
                  <div className="space-y-3">
                    {selectedProgram.manual_tests.map((test) => (
                      <div
                        key={test.id}
                        className="rounded-lg border border-zinc-800 bg-zinc-950 p-4"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="font-semibold">{test.title}</div>
                            <div className="text-sm text-zinc-400">{test.status}</div>
                          </div>
                          <button
                            onClick={() => deleteManualTest(test.id)}
                            className="rounded-md bg-red-600 px-3 py-1 text-sm font-semibold text-white"
                          >
                            Delete
                          </button>
                        </div>
                        <p className="mt-3 text-sm text-zinc-300">{test.hypothesis}</p>
                        <p className="mt-2 text-sm text-zinc-400">
                          Payload: {test.payload || "—"}
                        </p>
                        <p className="mt-2 text-sm text-zinc-400">
                          Evidence: {test.evidence || "—"}
                        </p>
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}

          {selectedProgram && activeSection === "findings" && (
            <div className="space-y-6">
              <SectionHeader
                title="Findings"
                description="Track validated issues before drafting the final report."
              />

              <div className="grid gap-6 xl:grid-cols-2">
                <Panel title="Add Finding">
                  <div className="grid gap-3">
                    <Input
                      label="Title"
                      value={findingForm.title}
                      onChange={(v) => setFindingForm({ ...findingForm, title: v })}
                    />
                    <div className="grid gap-3 md:grid-cols-3">
                      <Input
                        label="Severity"
                        value={findingForm.severity}
                        onChange={(v) => setFindingForm({ ...findingForm, severity: v })}
                      />
                      <Input
                        label="Asset"
                        value={findingForm.asset}
                        onChange={(v) => setFindingForm({ ...findingForm, asset: v })}
                      />
                      <Input
                        label="Status"
                        value={findingForm.status}
                        onChange={(v) => setFindingForm({ ...findingForm, status: v })}
                      />
                    </div>
                    <Textarea
                      label="Summary"
                      value={findingForm.summary}
                      onChange={(v) => setFindingForm({ ...findingForm, summary: v })}
                    />
                    <Textarea
                      label="Steps"
                      value={findingForm.steps}
                      onChange={(v) => setFindingForm({ ...findingForm, steps: v })}
                    />
                    <Textarea
                      label="Impact"
                      value={findingForm.impact}
                      onChange={(v) => setFindingForm({ ...findingForm, impact: v })}
                    />
                    <Textarea
                      label="Remediation"
                      value={findingForm.remediation}
                      onChange={(v) =>
                        setFindingForm({ ...findingForm, remediation: v })
                      }
                    />
                    <button
                      onClick={addFinding}
                      className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
                    >
                      Save Finding
                    </button>
                  </div>
                </Panel>

                <Panel title="Finding Tracker">
                  <div className="space-y-3">
                    {selectedProgram.findings.map((finding) => (
                      <div
                        key={finding.id}
                        className="rounded-lg border border-zinc-800 bg-zinc-950 p-4"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="font-semibold">{finding.title}</div>
                            <div className="text-sm text-zinc-400">
                              {finding.asset || "Unknown asset"} • {finding.severity} • {finding.status}
                            </div>
                          </div>
                          <button
                            onClick={() => deleteFinding(finding.id)}
                            className="rounded-md bg-red-600 px-3 py-1 text-sm font-semibold text-white"
                          >
                            Delete
                          </button>
                        </div>
                        <p className="mt-3 text-sm text-zinc-300">{finding.summary || "—"}</p>
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>
            </div>
          )}

          {selectedProgram && activeSection === "reports" && (
            <div className="space-y-6">
              <SectionHeader
                title="Reports"
                description="Draft submission-ready reports from validated findings."
              />

              <div className="grid gap-6 xl:grid-cols-2">
                <Panel title="Draft Report">
                  <div className="grid gap-3">
                    <div>
                      <label className="mb-2 block text-sm font-semibold">Link Finding</label>
                      <select
                        className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm"
                        value={reportForm.finding_id}
                        onChange={(e) => {
                          const findingId = e.target.value;
                          const finding = selectedProgram.findings.find((f) => f.id === findingId);
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
                        {selectedProgram.findings.map((finding) => (
                          <option key={finding.id} value={finding.id}>
                            {finding.title}
                          </option>
                        ))}
                      </select>
                    </div>

                    <Input
                      label="Report Title"
                      value={reportForm.title}
                      onChange={(v) => setReportForm({ ...reportForm, title: v })}
                    />
                    <Textarea
                      label="Summary"
                      value={reportForm.summary}
                      onChange={(v) => setReportForm({ ...reportForm, summary: v })}
                    />
                    <Textarea
                      label="Steps to Reproduce"
                      value={reportForm.steps}
                      onChange={(v) => setReportForm({ ...reportForm, steps: v })}
                    />
                    <Textarea
                      label="Impact"
                      value={reportForm.impact}
                      onChange={(v) => setReportForm({ ...reportForm, impact: v })}
                    />
                    <Textarea
                      label="Remediation"
                      value={reportForm.remediation}
                      onChange={(v) => setReportForm({ ...reportForm, remediation: v })}
                    />
                    <div className="grid gap-3 md:grid-cols-2">
                      <Input
                        label="CWE"
                        value={reportForm.cwe}
                        onChange={(v) => setReportForm({ ...reportForm, cwe: v })}
                      />
                      <Input
                        label="CVSS"
                        value={reportForm.cvss}
                        onChange={(v) => setReportForm({ ...reportForm, cvss: v })}
                      />
                    </div>
                    <button
                      onClick={addReport}
                      className="rounded-md bg-white px-4 py-2 text-sm font-semibold text-black"
                    >
                      Save Report
                    </button>
                  </div>
                </Panel>

                <Panel title="Report Preview">
                  <pre className="whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950 p-4 text-sm text-zinc-300">
                    {generateReportPreview()}
                  </pre>

                  <div className="mt-6 space-y-3">
                    {selectedProgram.reports.map((report) => (
                      <div
                        key={report.id}
                        className="rounded-lg border border-zinc-800 bg-zinc-950 p-4"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="font-semibold">{report.title}</div>
                            <div className="text-sm text-zinc-400">
                              CWE: {report.cwe || "—"} • CVSS: {report.cvss || "—"} • {report.status}
                            </div>
                          </div>
                          <button
                            onClick={() => deleteReport(report.id)}
                            className="rounded-md bg-red-600 px-3 py-1 text-sm font-semibold text-white"
                          >
                            Delete
                          </button>
                        </div>
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

function DashboardCard({ title, value }: { title: string; value: number }) {
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-5">
      <div className="text-sm text-zinc-400">{title}</div>
      <div className="mt-2 text-3xl font-bold">{value}</div>
    </div>
  );
}

function Panel({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-900 p-5">
      <h3 className="mb-4 text-xl font-semibold">{title}</h3>
      {children}
    </div>
  );
}

function SectionHeader({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div>
      <h2 className="text-3xl font-bold">{title}</h2>
      <p className="mt-2 text-zinc-400">{description}</p>
    </div>
  );
}

function Input({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div>
      <label className="mb-2 block text-sm font-semibold">{label}</label>
      <input
        className="w-full rounded-md border border-zinc-700 bg-zinc-950 p-2 text-sm"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function Textarea({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div>
      <label className="mb-2 block text-sm font-semibold">{label}</label>
      <textarea
        rows={4}
        className="w-full rounded-md border border-zinc-700 bg-zinc-950 p-2 text-sm"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="mb-3">
      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
        {label}
      </div>
      <div className="mt-1 text-sm text-zinc-200">{value}</div>
    </div>
  );
}

function ListCard({
  title,
  subtitle,
  onDelete,
}: {
  title: string;
  subtitle: string;
  onDelete: () => void;
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border border-zinc-800 bg-zinc-950 p-3">
      <div>
        <div className="font-semibold">{title}</div>
        <div className="text-sm text-zinc-400">{subtitle}</div>
      </div>
      <button
        onClick={onDelete}
        className="rounded-md bg-red-600 px-3 py-1 text-sm font-semibold text-white"
      >
        Delete
      </button>
    </div>
  );
}