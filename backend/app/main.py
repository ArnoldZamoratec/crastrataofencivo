"""FastAPI application entrypoint for the RAT Detection Lab backend.

Defensive / simulation-only. Bound to localhost / the private lab network by
default. Security headers, CORS, and request-size limits are applied here.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response

from .api.routes import router as api_router
from .config import get_settings
from .database import init_db
from .state import lab_state
from .websocket.lab import router as ws_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    lab_state.seed_demo_device()
    yield


app = FastAPI(
    title="Android RAT Detection Lab",
    version="0.1.0",
    description="Defensive, simulation-only educational lab backend.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    # Request-size guard for REST payloads (DoS defense).
    body = await request.body()
    if len(body) > settings.max_payload_bytes:
        return Response(status_code=413, content="payload too large")

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request._receive = receive  # re-inject the consumed body
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(api_router)
app.include_router(ws_router)
