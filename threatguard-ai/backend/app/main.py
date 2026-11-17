import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for candidate in (PROJECT_ROOT, BACKEND_ROOT):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from backend.app.config import APP_NAME, FASTAPI_HOST, FASTAPI_PORT, JWT_SECRET_KEY
from backend.app.database.connection import close_client, get_db
from backend.app.database.init_db import initialize_database
from backend.app.routes.auth import router as auth_router
from backend.app.routes.chat import router as chat_router
from backend.app.routes.dashboard import router as dashboard_router
from backend.app.routes.health import health_router
from backend.app.routes.knowledge import router as knowledge_router
from backend.app.routes.organizations import router as organizations_router
from backend.app.routes.scanner import router as scanner_router
from backend.app.routes.tenants import router as tenants_router
from backend.app.routes.threats import router as threats_router

@asynccontextmanager
async def lifespan(_: FastAPI):
    if len(JWT_SECRET_KEY) < 32:
        raise RuntimeError("JWT_SECRET_KEY must be configured with at least 32 characters before startup.")
    initialize_database(get_db())
    try:
        yield
    finally:
        close_client()


app = FastAPI(title=APP_NAME, version="0.1.0", lifespan=lifespan)


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError) -> JSONResponse:
    status_code = 403 if "tenant" in str(exc).lower() or "org_id" in str(exc).lower() else 400
    return JSONResponse(status_code=status_code, content={"detail": str(exc)})


app.include_router(auth_router)
app.include_router(chat_router)
app.include_router(dashboard_router)
app.include_router(health_router)
app.include_router(knowledge_router)
app.include_router(organizations_router)
app.include_router(scanner_router)
app.include_router(tenants_router)
app.include_router(threats_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=FASTAPI_HOST, port=FASTAPI_PORT, reload=False)
