from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "https://vardr-map.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "VardrMap API is running"}

@app.get("/health")
def health_check():
    return {"status": "ok"}

targets = []

@app.get("/targets")
def get_targets():
    return {"targets": targets}

@app.post("/targets")
def add_target(target: dict):
    new_target = {
        "name": target.get("name"),
        "notes": target.get("notes", ""),
        "status": "new"
    }
    targets.append(new_target)
    return {"message": "Target added", "target": new_target}

@app.delete("/targets/{target_index}")
def delete_target(target_index: int):
    if 0 <= target_index < len(targets):
        deleted = targets.pop(target_index)
        return {"message": "Target deleted", "target": deleted}
    return {"message": "Target not found"}