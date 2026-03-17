from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Any
from uuid import uuid4
import json

app = FastAPI(title="VardrMap API")

origins = [
    "http://localhost:3000",
    "https://vardr-map.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

programs: list[dict[str, Any]] = []


def generate_id() -> str:
    return str(uuid4())


def get_program_or_404(program_id: str) -> dict[str, Any]:
    for program in programs:
        if program["id"] == program_id:
            return program
    raise HTTPException(status_code=404, detail="Program not found")


def parse_json_or_jsonl(raw_bytes: bytes) -> list[dict[str, Any]] | dict[str, Any]:
    text = raw_bytes.decode("utf-8", errors="ignore").strip()
    if not text:
        return []

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        items = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


def normalize_to_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            return [item for item in payload["results"] if isinstance(item, dict)]
        return [payload]
    return []


def parse_ffuf(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    parsed = []
    for item in items:
        input_data = item.get("input", {}) or {}
        fuzz_value = input_data.get("FUZZ", "")
        parsed.append(
            {
                "id": generate_id(),
                "source": "ffuf",
                "url": item.get("url", ""),
                "path": fuzz_value,
                "status_code": item.get("status", 0),
                "length": item.get("length", 0),
                "words": item.get("words", 0),
                "lines": item.get("lines", 0),
                "content_type": item.get("content-type", ""),
                "notes": "",
            }
        )
    return parsed


def parse_httpx(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    parsed = []
    for item in items:
        parsed.append(
            {
                "id": generate_id(),
                "source": "httpx",
                "url": item.get("url", ""),
                "host": item.get("host", ""),
                "title": item.get("title", ""),
                "status_code": item.get("status-code", item.get("status_code", 0)),
                "webserver": item.get("webserver", ""),
                "port": item.get("port", ""),
                "tech": item.get("tech", item.get("technologies", [])),
                "notes": "",
            }
        )
    return parsed


def parse_nuclei(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    parsed = []
    for item in items:
        info = item.get("info", {}) or {}
        parsed.append(
            {
                "id": generate_id(),
                "source": "nuclei",
                "template_id": item.get("template-id", item.get("templateID", "")),
                "title": info.get("name", item.get("template-id", "Unnamed finding")),
                "severity": info.get("severity", "info"),
                "asset": item.get("matched-at", item.get("host", item.get("url", ""))),
                "matched_at": item.get("matched-at", ""),
                "type": item.get("type", ""),
                "description": info.get("description", ""),
                "status": "candidate",
            }
        )
    return parsed


class ProgramCreate(BaseModel):
    name: str
    platform: Optional[str] = ""
    program_url: Optional[str] = ""
    scope_summary: Optional[str] = ""
    severity_guidance: Optional[str] = ""
    safe_harbor_notes: Optional[str] = ""


class ProgramUpdate(BaseModel):
    name: Optional[str] = None
    platform: Optional[str] = None
    program_url: Optional[str] = None
    scope_summary: Optional[str] = None
    severity_guidance: Optional[str] = None
    safe_harbor_notes: Optional[str] = None


class ScopeItemCreate(BaseModel):
    value: str
    kind: Optional[str] = "domain"
    notes: Optional[str] = ""


class ManualTestCreate(BaseModel):
    title: str
    hypothesis: Optional[str] = ""
    payload: Optional[str] = ""
    evidence: Optional[str] = ""
    status: Optional[str] = "new"


class FindingCreate(BaseModel):
    title: str
    severity: Optional[str] = "info"
    asset: Optional[str] = ""
    status: Optional[str] = "new"
    summary: Optional[str] = ""
    steps: Optional[str] = ""
    impact: Optional[str] = ""
    remediation: Optional[str] = ""


class ReportCreate(BaseModel):
    finding_id: Optional[str] = ""
    title: str
    summary: Optional[str] = ""
    steps: Optional[str] = ""
    impact: Optional[str] = ""
    remediation: Optional[str] = ""
    cwe: Optional[str] = ""
    cvss: Optional[str] = ""
    status: Optional[str] = "draft"


@app.get("/")
def read_root():
    return {"message": "VardrMap API is running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/programs")
def get_programs():
    return {"programs": programs}


@app.post("/programs")
def create_program(payload: ProgramCreate):
    program = {
        "id": generate_id(),
        "name": payload.name,
        "platform": payload.platform or "",
        "program_url": payload.program_url or "",
        "scope_summary": payload.scope_summary or "",
        "severity_guidance": payload.severity_guidance or "",
        "safe_harbor_notes": payload.safe_harbor_notes or "",
        "scope": {"in": [], "out": []},
        "imports": [],
        "recon": [],
        "scans": [],
        "manual_tests": [],
        "findings": [],
        "reports": [],
    }
    programs.append(program)
    return program


@app.get("/programs/{program_id}")
def get_program(program_id: str):
    return get_program_or_404(program_id)


@app.patch("/programs/{program_id}")
def update_program(program_id: str, payload: ProgramUpdate):
    program = get_program_or_404(program_id)
    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        program[key] = value
    return program


@app.delete("/programs/{program_id}")
def delete_program(program_id: str):
    global programs
    before = len(programs)
    programs = [p for p in programs if p["id"] != program_id]
    if len(programs) == before:
        raise HTTPException(status_code=404, detail="Program not found")
    return {"message": "Program deleted"}


@app.post("/programs/{program_id}/scope/in")
def add_in_scope_item(program_id: str, payload: ScopeItemCreate):
    program = get_program_or_404(program_id)
    item = {
        "id": generate_id(),
        "value": payload.value,
        "kind": payload.kind or "domain",
        "notes": payload.notes or "",
    }
    program["scope"]["in"].append(item)
    return item


@app.post("/programs/{program_id}/scope/out")
def add_out_scope_item(program_id: str, payload: ScopeItemCreate):
    program = get_program_or_404(program_id)
    item = {
        "id": generate_id(),
        "value": payload.value,
        "kind": payload.kind or "domain",
        "notes": payload.notes or "",
    }
    program["scope"]["out"].append(item)
    return item


@app.delete("/programs/{program_id}/scope/{scope_type}/{item_id}")
def delete_scope_item(program_id: str, scope_type: str, item_id: str):
    program = get_program_or_404(program_id)
    if scope_type not in ["in", "out"]:
        raise HTTPException(status_code=400, detail="Invalid scope type")

    before = len(program["scope"][scope_type])
    program["scope"][scope_type] = [
        item for item in program["scope"][scope_type] if item["id"] != item_id
    ]

    if len(program["scope"][scope_type]) == before:
        raise HTTPException(status_code=404, detail="Scope item not found")

    return {"message": "Scope item deleted"}


@app.get("/programs/{program_id}/recon")
def get_recon(program_id: str):
    program = get_program_or_404(program_id)
    return {"recon": program["recon"]}


@app.get("/programs/{program_id}/scans")
def get_scans(program_id: str):
    program = get_program_or_404(program_id)
    return {"scans": program["scans"]}


@app.get("/programs/{program_id}/manual-tests")
def get_manual_tests(program_id: str):
    program = get_program_or_404(program_id)
    return {"manual_tests": program["manual_tests"]}


@app.post("/programs/{program_id}/manual-tests")
def add_manual_test(program_id: str, payload: ManualTestCreate):
    program = get_program_or_404(program_id)
    test = {
        "id": generate_id(),
        "title": payload.title,
        "hypothesis": payload.hypothesis or "",
        "payload": payload.payload or "",
        "evidence": payload.evidence or "",
        "status": payload.status or "new",
    }
    program["manual_tests"].append(test)
    return test


@app.delete("/programs/{program_id}/manual-tests/{test_id}")
def delete_manual_test(program_id: str, test_id: str):
    program = get_program_or_404(program_id)
    before = len(program["manual_tests"])
    program["manual_tests"] = [t for t in program["manual_tests"] if t["id"] != test_id]
    if len(program["manual_tests"]) == before:
        raise HTTPException(status_code=404, detail="Manual test not found")
    return {"message": "Manual test deleted"}


@app.get("/programs/{program_id}/findings")
def get_findings(program_id: str):
    program = get_program_or_404(program_id)
    return {"findings": program["findings"]}


@app.post("/programs/{program_id}/findings")
def add_finding(program_id: str, payload: FindingCreate):
    program = get_program_or_404(program_id)
    finding = {
        "id": generate_id(),
        "title": payload.title,
        "severity": payload.severity or "info",
        "asset": payload.asset or "",
        "status": payload.status or "new",
        "summary": payload.summary or "",
        "steps": payload.steps or "",
        "impact": payload.impact or "",
        "remediation": payload.remediation or "",
    }
    program["findings"].append(finding)
    return finding


@app.patch("/programs/{program_id}/findings/{finding_id}")
def update_finding(program_id: str, finding_id: str, payload: FindingCreate):
    program = get_program_or_404(program_id)
    for finding in program["findings"]:
        if finding["id"] == finding_id:
            finding.update(payload.model_dump())
            return finding
    raise HTTPException(status_code=404, detail="Finding not found")


@app.delete("/programs/{program_id}/findings/{finding_id}")
def delete_finding(program_id: str, finding_id: str):
    program = get_program_or_404(program_id)
    before = len(program["findings"])
    program["findings"] = [f for f in program["findings"] if f["id"] != finding_id]
    if len(program["findings"]) == before:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"message": "Finding deleted"}


@app.get("/programs/{program_id}/reports")
def get_reports(program_id: str):
    program = get_program_or_404(program_id)
    return {"reports": program["reports"]}


@app.post("/programs/{program_id}/reports")
def add_report(program_id: str, payload: ReportCreate):
    program = get_program_or_404(program_id)
    report = {
        "id": generate_id(),
        "finding_id": payload.finding_id or "",
        "title": payload.title,
        "summary": payload.summary or "",
        "steps": payload.steps or "",
        "impact": payload.impact or "",
        "remediation": payload.remediation or "",
        "cwe": payload.cwe or "",
        "cvss": payload.cvss or "",
        "status": payload.status or "draft",
    }
    program["reports"].append(report)
    return report


@app.delete("/programs/{program_id}/reports/{report_id}")
def delete_report(program_id: str, report_id: str):
    program = get_program_or_404(program_id)
    before = len(program["reports"])
    program["reports"] = [r for r in program["reports"] if r["id"] != report_id]
    if len(program["reports"]) == before:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"message": "Report deleted"}


@app.post("/programs/{program_id}/imports")
async def import_results(
    program_id: str,
    tool_type: str = Form(...),
    file: UploadFile = File(...),
):
    program = get_program_or_404(program_id)
    raw = await file.read()
    parsed = parse_json_or_jsonl(raw)
    items = normalize_to_list(parsed)

    import_record = {
        "id": generate_id(),
        "tool_type": tool_type,
        "filename": file.filename,
        "imported_count": 0,
    }

    if tool_type == "ffuf":
        recon_items = parse_ffuf(items)
        program["recon"].extend(recon_items)
        import_record["imported_count"] = len(recon_items)

    elif tool_type == "httpx":
        recon_items = parse_httpx(items)
        program["recon"].extend(recon_items)
        import_record["imported_count"] = len(recon_items)

    elif tool_type == "nuclei":
        scan_items = parse_nuclei(items)
        program["scans"].extend(scan_items)
        import_record["imported_count"] = len(scan_items)

    else:
        raise HTTPException(status_code=400, detail="Unsupported tool type")

    program["imports"].append(import_record)
    return {
        "message": "Import complete",
        "import_record": import_record,
        "program": program,
    }