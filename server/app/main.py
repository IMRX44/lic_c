"""
FastAPI application entry point.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

from app.config import settings
from app.database import init_db
from app.crypto import load_or_generate_keys
from app.auth import create_initial_admin
from app.database import AsyncSessionLocal
from app.routers import license_api, admin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing database...")
    await init_db()

    logger.info("Loading/generating Ed25519 keys...")
    load_or_generate_keys(
        settings.ed25519_private_key_path,
        settings.ed25519_public_key_path,
    )

    logger.info("Creating initial admin if needed...")
    async with AsyncSessionLocal() as db:
        await create_initial_admin(db)

    logger.info("Server ready.")
    yield
    # Shutdown
    logger.info("Shutting down.")


app = FastAPI(
    title="License System",
    version="1.0.0",
    docs_url=None,  # disable Swagger in production
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static files & templates
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
panel_static = os.path.join(BASE_DIR, "panel", "static")
panel_templates = os.path.join(BASE_DIR, "panel", "templates")

if os.path.exists(panel_static):
    app.mount("/static", StaticFiles(directory=panel_static), name="static")

templates = Jinja2Templates(directory=panel_templates)

# Routers
app.include_router(license_api.router)
app.include_router(admin.router)


# ─── Panel routes ─────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse("/panel")


@app.get("/panel", response_class=HTMLResponse, include_in_schema=False)
async def panel_index(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/panel/login", response_class=HTMLResponse, include_in_schema=False)
async def panel_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/panel/licenses", response_class=HTMLResponse, include_in_schema=False)
async def panel_licenses(request: Request):
    return templates.TemplateResponse("licenses.html", {"request": request})


@app.get("/panel/products", response_class=HTMLResponse, include_in_schema=False)
async def panel_products(request: Request):
    return templates.TemplateResponse("products.html", {"request": request})


@app.get("/panel/audit", response_class=HTMLResponse, include_in_schema=False)
async def panel_audit(request: Request):
    return templates.TemplateResponse("audit.html", {"request": request})


@app.get("/health")
async def health():
    return {"status": "ok"}
