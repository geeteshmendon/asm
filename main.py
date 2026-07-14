from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from internal.db.database import engine, Base
from internal.api.routes import router as api_router
from internal.scheduler.scheduler import start_scheduler
import os

Base.metadata.create_all(bind=engine)

ALLOWED_ORIGINS = os.environ.get("ASM_ALLOWED_ORIGINS", "*")

app = FastAPI(
    title="Attack Surface Manager",
    version="2.0.0",
    description="Full-featured ASM tool with passive recon, SSL analysis, webhook alerts, and more",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

os.makedirs("web/static", exist_ok=True)
os.makedirs("web/static/screenshots", exist_ok=True)

app.mount("/static", StaticFiles(directory="web/static"), name="static")


@app.get("/")
def index():
    return FileResponse("web/templates/index.html")


@app.get("/targets/{target_id}")
def asset_detail(target_id: int):
    return FileResponse("web/templates/index.html")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    start_scheduler(interval_hours=24)
    uvicorn.run(app, host="0.0.0.0", port=port)
