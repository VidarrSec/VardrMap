import json
import os
from pathlib import Path
from typing import Any, Literal, Optional
from uuid import uuid4

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from pydantic import BaseModel, Field


# -----------------------------------------------------------------------------
# Environment-driven config only
# Never hardcode secrets in code.
# -----------------------------------------------------------------------------

ENV = os.getenv("ENV") or os.getenv("RAILWAY_ENVIRONMENT_NAME", "development")
BACKEND_JWT_SECRET = os.getenv("BACKEND_JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "2097152"))

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,https://vardr-map.vercel.app",
    ).split(",")
    if origin.strip()
]

ALLOWED_EXTENSIONS = {".json", ".jsonl"}
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/x-ndjson",
    "application/octet-stream",
    "text/plain",
}


# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------

app = FastAPI(title="VardrMap API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# -----------------------------------------------------------------------------
# Temporary in-memory storage
# NOTE: This is still temporary and not suitable long-term for a public app.
# -----------------------------------------------------------------------------

programs: list[dict[str, Any]] = []


# -----------------------------------------------------------------------------
# Enums / strict types
# -----------------------------------------------------------------------------

Severity = Literal["info", "low", "medium", "high", "critical"]
FindingStatus = Literal["new", "candidate", "triaged", "in_progress", "closed"]
ManualStatus = Literal["new", "in_progress", "validated", "closed"]
ScopeKind = Literal["domain", "subdomain", "url", "cidr", "api", "mobile"]
ReportStatus = Literal["draft", "submitted", "accepted", "duplicate", "informative", "resolved"]
ToolType = Literal["ffuf", "httpx", "nuclei"]


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

class ProgramCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    platform: Optional[str] = Field(default="", max_length=80)
    program_url: Optional[str] = Field(default="", max_length=500)
    scope_summary: Optional[str] = Field(default="", max_length=5000)
    severity_guidance: Optional[str] = Field(default="", max_length=5000)
    safe_harbor_notes: Optional[str] = Field(default="", max_length=5000)


class ProgramUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    platform: Optional[str] = Field(default=None, max_length=80)
    program_url: Optional[str] = Field(default=None, max_length=500)
    scope_summary: Optional[str] = Field(default=None, max_length=5000)
    severity_guidance: Optional[str] = Field(default=None, max_length=5000)
    safe_harbor_notes: Optional[str] = Field(default=None, max_length=5000)


class ScopeItemCreate(BaseModel):
    value: str = Field(min_length=1, max_length=500)
    kind: ScopeKind = "domain"
    notes: Optional[str] = Field(default="", max_length=2000)


class ManualTestCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    hypothesis: Optional[str] = Field(default="", max_length=5000)
    payload: Optional[str] = Field(default="", max_length=10000)
    evidence: Optional[str] = Field(default="", max_length=10000)
    status: ManualStatus = "new"


class FindingCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: Severity = "info"
    asset: Optional[str] = Field(default="", max_length=500)
    status: FindingStatus = "new"
    summary: Optional[str] = Field(default="", max_length=5000)
    steps: Optional[str] = Field(default="", max_length=10000)
    impact: Optional[str] = Field(default="", max_length=5000)
    remediation: Optional[str] = Field(default="", max_length=5000)


class ReportCreate(BaseModel):
    finding_id: Optional[str] = Field(default="", max_length=100)
    title: str = Field(min_length=1, max_length=200)
    summary: Optional[str] = Field(default="", max_length=5000)
    steps: Optional[str] = Field(default="", max_length=10000)
    impact: Optional[str] = Field(default="", max_length=5000)
    remediation: Optional[str] = Field(default="", max_length=5000)
    cwe: Optional[str] = Field(default="", max_length=50)
    cvss: Optional[str] = Field(default="", max_length=50)
    status: ReportStatus = "draft"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def generate_id() -> str:
    return str(uuid4())


def get_current_user(authorization: str | None = Header(default=None)) -> dict[str, str]:
    if not BACKEND_JWT_SECRET:
        raise HTTPException(status_code=500, detail="Server auth not configured")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(
            token,
            BACKEND_JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience="vardrmap-backend",
            issuer="vardrmap-frontend",
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Unauthorized")

    github_id = payload.get("sub")
    if not github_id:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {
        "github_id": str(github_id),
        "username": str(payload.get("username", "")),
        "email": str(payload.get("email", "")),
    }


def get_program_or_404(program_id: str, current_user: dict[str, str]) -> dict[str, Any]:
    for program in programs:
        if (
            program["id"] == program_id
            and program["owner_github_id"] == current_user["github_id"]
        ):
            return program
    raise HTTPException(status_code=404, detail="Program not found")


def parse_json_or_jsonl(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # JSONL
    if "\n" in text:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        try:
            return [json.loads(line) for line in lines]
        except json.JSONDecodeError:
            pass

    # JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON/JSONL: {exc.msg}")


def normalize_to_list(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, list):
        out: list[dict[str, Any]] = []
        for item in parsed:
            if isinstance(item, dict):
                out.append(item)
        return out

    if isinstance(parsed, dict):
        if isinstance(parsed.get("results"), list):
            return [item for item in parsed["results"] if isinstance(item, dict)]
        return [parsed]

    raise HTTPException(status_code=400, detail="Unsupported JSON structure")


def parse_ffuf(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recon_items: list[dict[str, Any]] = []

    for item in items:
        url = item.get("url") or item.get("input", {}).get("FUZZ")
        recon_items.append(
            {
                "id": generate_id(),
                "source": "ffuf",
                "url": url or "",
                "path": str(item.get("input", {}).get("FUZZ", "")),
                "status_code": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "content_type": item.get("content-type") or item.get("content_type") or "",
                "notes": "",
            }
        )

    return recon_items


def parse_httpx(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recon_items: list[dict[str, Any]] = []

    for item in items:
        tech_value = item.get("tech") or item.get("technologies") or []
        if isinstance(tech_value, list):
            tech_list = [str(t) for t in tech_value]
        else:
            tech_list = [str(tech_value)] if tech_value else []

        recon_items.append(
            {
                "id": generate_id(),
                "source": "httpx",
                "url": item.get("url") or "",
                "host": item.get("host") or "",
                "title": item.get("title") or "",
                "status_code": item.get("status-code") or item.get("status_code"),
                "webserver": item.get("webserver") or "",
                "port": item.get("port") or "",
                "tech": tech_list,
                "content_type": item.get("content-type") or item.get("content_type") or "",
                "notes": "",
            }
        )

    return recon_items


def parse_nuclei(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scan_items: list[dict[str, Any]] = []

    for item in items:
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}

        scan_items.append(
            {
                "id": generate_id(),
                "source": "nuclei",
                "template_id": item.get("template-id") or item.get("templateID") or "",
                "title": info.get("name") or item.get("matcher-name") or "Untitled Finding",
                "severity": info.get("severity") or "info",
                "asset": item.get("matched-at") or item.get("host") or "",
                "matched_at": item.get("matched-at") or "",
                "type": item.get("type") or "",
                "description": info.get("description") or "",
                "status": "new",
                "cwe": classification.get("cwe-id") or "",
                "cvss": classification.get("cvss-score") or "",
            }
        )

    return scan_items


# -----------------------------------------------------------------------------
# Public routes
# -----------------------------------------------------------------------------

@app.get("/")
def read_root():
    return {"message": "VardrMap API is running", "environment": ENV}


@app.get("/health")
def health_check():
    return {"status": "ok", "environment": ENV}


# -----------------------------------------------------------------------------
# Protected test route
# -----------------------------------------------------------------------------

@app.get("/me")
def me(current_user: dict[str, str] = Depends(get_current_user)):
    return current_user


# -----------------------------------------------------------------------------
# Programs
# -----------------------------------------------------------------------------

@app.get("/programs")
def get_programs(current_user: dict[str, str] = Depends(get_current_user)):
    owned_programs = [
        p for p in programs if p["owner_github_id"] == current_user["github_id"]
    ]
    return {"programs": owned_programs}


@app.post("/programs")
def create_program(
    payload: ProgramCreate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = {
        "id": generate_id(),
        "owner_github_id": current_user["github_id"],
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
def get_program(
    program_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    return get_program_or_404(program_id, current_user)


@app.patch("/programs/{program_id}")
def update_program(
    program_id: str,
    payload: ProgramUpdate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        program[key] = value
    return program


@app.delete("/programs/{program_id}")
def delete_program(
    program_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    global programs
    before = len(programs)
    programs = [
        p for p in programs
        if not (
            p["id"] == program_id
            and p["owner_github_id"] == current_user["github_id"]
        )
    ]
    if len(programs) == before:
        raise HTTPException(status_code=404, detail="Program not found")
    return {"message": "Program deleted"}


# -----------------------------------------------------------------------------
# Scope
# -----------------------------------------------------------------------------

@app.post("/programs/{program_id}/scope/in")
def add_in_scope_item(
    program_id: str,
    payload: ScopeItemCreate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    item = {
        "id": generate_id(),
        "value": payload.value,
        "kind": payload.kind,
        "notes": payload.notes or "",
    }
    program["scope"]["in"].append(item)
    return item


@app.post("/programs/{program_id}/scope/out")
def add_out_scope_item(
    program_id: str,
    payload: ScopeItemCreate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    item = {
        "id": generate_id(),
        "value": payload.value,
        "kind": payload.kind,
        "notes": payload.notes or "",
    }
    program["scope"]["out"].append(item)
    return item


@app.delete("/programs/{program_id}/scope/{scope_type}/{item_id}")
def delete_scope_item(
    program_id: str,
    scope_type: str,
    item_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)

    if scope_type not in ["in", "out"]:
        raise HTTPException(status_code=400, detail="Invalid scope type")

    before = len(program["scope"][scope_type])
    program["scope"][scope_type] = [
        item for item in program["scope"][scope_type] if item["id"] != item_id
    ]

    if len(program["scope"][scope_type]) == before:
        raise HTTPException(status_code=404, detail="Scope item not found")

    return {"message": "Scope item deleted"}


# -----------------------------------------------------------------------------
# Recon / scans
# -----------------------------------------------------------------------------

@app.get("/programs/{program_id}/recon")
def get_recon(
    program_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    return {"recon": program["recon"]}


@app.get("/programs/{program_id}/scans")
def get_scans(
    program_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    return {"scans": program["scans"]}


# -----------------------------------------------------------------------------
# Manual tests
# -----------------------------------------------------------------------------

@app.get("/programs/{program_id}/manual-tests")
def get_manual_tests(
    program_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    return {"manual_tests": program["manual_tests"]}


@app.post("/programs/{program_id}/manual-tests")
def add_manual_test(
    program_id: str,
    payload: ManualTestCreate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    test = {
        "id": generate_id(),
        "title": payload.title,
        "hypothesis": payload.hypothesis or "",
        "payload": payload.payload or "",
        "evidence": payload.evidence or "",
        "status": payload.status,
    }
    program["manual_tests"].append(test)
    return test


@app.delete("/programs/{program_id}/manual-tests/{test_id}")
def delete_manual_test(
    program_id: str,
    test_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    before = len(program["manual_tests"])
    program["manual_tests"] = [t for t in program["manual_tests"] if t["id"] != test_id]
    if len(program["manual_tests"]) == before:
        raise HTTPException(status_code=404, detail="Manual test not found")
    return {"message": "Manual test deleted"}


# -----------------------------------------------------------------------------
# Findings
# -----------------------------------------------------------------------------

@app.get("/programs/{program_id}/findings")
def get_findings(
    program_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    return {"findings": program["findings"]}


@app.post("/programs/{program_id}/findings")
def add_finding(
    program_id: str,
    payload: FindingCreate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    finding = {
        "id": generate_id(),
        "title": payload.title,
        "severity": payload.severity,
        "asset": payload.asset or "",
        "status": payload.status,
        "summary": payload.summary or "",
        "steps": payload.steps or "",
        "impact": payload.impact or "",
        "remediation": payload.remediation or "",
    }
    program["findings"].append(finding)
    return finding


@app.patch("/programs/{program_id}/findings/{finding_id}")
def update_finding(
    program_id: str,
    finding_id: str,
    payload: FindingCreate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    for finding in program["findings"]:
        if finding["id"] == finding_id:
            finding.update(payload.model_dump())
            return finding
    raise HTTPException(status_code=404, detail="Finding not found")


@app.delete("/programs/{program_id}/findings/{finding_id}")
def delete_finding(
    program_id: str,
    finding_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    before = len(program["findings"])
    program["findings"] = [f for f in program["findings"] if f["id"] != finding_id]
    if len(program["findings"]) == before:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"message": "Finding deleted"}


# -----------------------------------------------------------------------------
# Reports
# -----------------------------------------------------------------------------

@app.get("/programs/{program_id}/reports")
def get_reports(
    program_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    return {"reports": program["reports"]}


@app.post("/programs/{program_id}/reports")
def add_report(
    program_id: str,
    payload: ReportCreate,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
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
        "status": payload.status,
    }
    program["reports"].append(report)
    return report


@app.delete("/programs/{program_id}/reports/{report_id}")
def delete_report(
    program_id: str,
    report_id: str,
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)
    before = len(program["reports"])
    program["reports"] = [r for r in program["reports"] if r["id"] != report_id]
    if len(program["reports"]) == before:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"message": "Report deleted"}


# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------

@app.post("/programs/{program_id}/imports")
async def import_results(
    program_id: str,
    tool_type: ToolType = Form(...),
    file: UploadFile = File(...),
    current_user: dict[str, str] = Depends(get_current_user),
):
    program = get_program_or_404(program_id, current_user)

    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .json and .jsonl files are allowed")

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported file type")

    raw = await file.read()

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    parsed = parse_json_or_jsonl(raw)
    items = normalize_to_list(parsed)

    import_record = {
        "id": generate_id(),
        "tool_type": tool_type,
        "filename": "redacted",
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

    program["imports"].append(import_record)

    return {
        "message": "Import complete",
        "import_record": import_record,
        "program": program,
    }