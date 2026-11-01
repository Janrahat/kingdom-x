"""FastAPI application for the KINGDOM X dashboard.

Routes
------
``GET /``            dashboard page
``GET /api/status``  registry with effective status per module
``GET /api/health``  host health summary
``GET /api/system``  platform and system snapshot
``GET /api/audit``   read-only host audit findings
``GET /api/tools``   installed security tooling

Every route is a GET and none takes a target, so the dashboard cannot be used
as a scan proxy. There is no authentication layer because there are no
privileged operations to protect — binding it to 127.0.0.1 is the security
control, and the docs say so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kingdomx.core import registry as reg
from kingdomx.core.config import Config
from kingdomx.core.platform_detect import current as current_platform

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse

    FASTAPI_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - fallback path
    FastAPI = None  # type: ignore[assignment]
    HTTPException = Exception  # type: ignore[assignment,misc]
    HTMLResponse = None  # type: ignore[assignment]
    JSONResponse = None  # type: ignore[assignment]
    FASTAPI_AVAILABLE = False

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _read_template(name: str) -> str:
    path = TEMPLATE_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"template not found: {path}")
    return path.read_text(encoding="utf-8")


def _status_payload() -> dict[str, Any]:
    counts = reg.REGISTRY.counts()
    by_section: dict[str, list[dict[str, Any]]] = {}
    for module in reg.REGISTRY.all():
        by_section.setdefault(module.section, []).append(module.to_dict())
    return {
        "tool": "KINGDOM X",
        "subtitle": "THE KING OF GLOBAL TECHNOLOGY",
        "tagline": "ONE PLATFORM. ALL TECHNOLOGIES. UNLIMITED INTELLIGENCE.",
        "counts": counts,
        "sections": {
            key: {
                "title": reg.SECTION_TITLES.get(key, key.upper()),
                "modules": sorted(mods, key=lambda m: m["key"]),
            }
            for key, mods in sorted(by_section.items())
        },
        "menu": [
            {"number": number, "title": title, "section": key, "live": live}
            for number, title, key, live in reg.menu_entries()
        ],
    }


def create_app(config: Config | None = None) -> Any:
    """Build the FastAPI app, or raise if FastAPI is not installed."""
    if not FASTAPI_AVAILABLE:
        raise RuntimeError(
            "FastAPI is not installed. Install it with: pip install 'kingdomx[web]'"
        )

    app = FastAPI(
        title="KINGDOM X",
        description="Read-only intelligence dashboard.",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
    )
    _config = config or Config.load()

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> Any:
        try:
            html = _read_template("dashboard.html")
        except FileNotFoundError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        payload = _status_payload()
        html = html.replace("__STATUS_JSON__", json.dumps(payload))
        return HTMLResponse(html)

    @app.get("/api/status")
    def api_status() -> Any:
        return JSONResponse(_status_payload())

    @app.get("/api/health")
    def api_health() -> Any:
        from kingdomx.computers.system import health_report

        return JSONResponse(health_report())

    @app.get("/api/system")
    def api_system() -> Any:
        from kingdomx.computers.system import collect

        return JSONResponse(
            {
                "platform": current_platform().to_dict(),
                "system": collect().to_dict(),
                "config": _config.summary(),
            }
        )

    @app.get("/api/audit")
    def api_audit() -> Any:
        from kingdomx.cybersecurity.audit import run_audit

        return JSONResponse(run_audit().to_dict())

    @app.get("/api/tools")
    def api_tools() -> Any:
        from kingdomx.cybersecurity.tools import detect_all, inventory_summary

        return JSONResponse(
            {
                "summary": inventory_summary(),
                "tools": [tool.to_dict() for tool in detect_all() if tool.present],
            }
        )

    @app.get("/api/module/{key}")
    def api_module(key: str) -> Any:
        module = reg.REGISTRY.get(key)
        if module is None:
            raise HTTPException(status_code=404, detail=f"unknown module '{key}'")
        return JSONResponse(module.to_dict())

    return app


def serve(*, host: str = "127.0.0.1", port: int = 8000, config: Config | None = None) -> None:
    """Run the dashboard with uvicorn."""
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "uvicorn is not installed. Install it with: pip install 'kingdomx[web]'"
        ) from exc

    if host not in {"127.0.0.1", "localhost", "::1"}:
        print(
            "WARNING: binding the dashboard to a non-loopback address exposes "
            "host diagnostics to your network. It is read-only, but restrict it with "
            "a firewall or a reverse proxy with authentication."
        )
    uvicorn.run(create_app(config), host=host, port=port, log_level="info")
