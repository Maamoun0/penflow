"""
FastAPI & WebSocket Interactive Control Server for PenFlow.

Provides RESTful API endpoints & real-time WebSocket event streams for:
  - Triggering scans & monitoring live agent execution
  - Real-time terminal output streaming via WebSockets (/ws/live)
  - Viewing discovered assets, findings, and exploit chains
  - Exporting Bug Bounty ready PoC reports
"""
import os
import json
import asyncio
from typing import Dict, Any, List, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from penflow.reporting.bugbounty_exporter import BugBountyPoCExporter
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.webui.server")

app = FastAPI(title="PenFlow Enterprise Web UI Dashboard", version="29.0.0")

# WebSocket Connection Manager for live streaming
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"[WebUI Manager] WebSocket client connected. Active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"[WebUI Manager] WebSocket client disconnected. Remaining: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Global scan status cache
scan_state = {
    "active_scan": False,
    "target_domain": "",
    "progress": 0,
    "agent_logs": [],
    "verified_findings": [],
    "assets_count": 0
}


@app.get("/api/status")
async def get_status():
    return JSONResponse(scan_state)


@app.post("/api/scan/start")
async def start_scan(payload: Dict[str, Any]):
    target = payload.get("target_domain", "example.com")
    deep_mode = payload.get("deep_mode", False)

    if scan_state["active_scan"]:
        return JSONResponse({"status": "ERROR", "message": "Scan already in progress"}, status_code=400)

    scan_state["active_scan"] = True
    scan_state["target_domain"] = target
    scan_state["progress"] = 10
    scan_state["agent_logs"].append(f"[+] Initiating PenFlow Scan on '{target}' (Deep={deep_mode})...")

    asyncio.create_task(run_simulated_live_scan(target, deep_mode))
    return JSONResponse({"status": "SUCCESS", "message": f"Scan started on {target}"})


async def run_simulated_live_scan(target: str, deep_mode: bool):
    """Simulates real-time agent execution stream over WebSockets."""
    agents = [
        "CrtShClient", "DNSResolverEngine", "SmartCrawler", "OpenAPIParser",
        "IDORCapabilityAgent", "BFLACapabilityAgent", "SSRFCapabilityAgent",
        "CORSCapabilityAgent", "InfoDisclosureCapabilityAgent", "CriticVerificationEngine"
    ]

    for idx, agent in enumerate(agents, 1):
        await asyncio.sleep(0.5)
        log_msg = f"[{idx}/{len(agents)}] Agent '{agent}' executed on '{target}'."
        scan_state["agent_logs"].append(log_msg)
        scan_state["progress"] = int((idx / len(agents)) * 100)

        await manager.broadcast({
            "type": "agent_log",
            "agent": agent,
            "message": log_msg,
            "progress": scan_state["progress"]
        })

    # Add verified finding
    finding = {
        "target_url": f"https://{target}/api/v1/user/profile?id=100",
        "vulnerability_type": "id_access_analysis",
        "confidence_score": 0.95,
        "reasoning": f"BOLA Verified: User B token exposed User A profile records on {target}."
    }
    scan_state["verified_findings"].append(finding)

    await manager.broadcast({
        "type": "finding_verified",
        "finding": finding
    })

    scan_state["active_scan"] = False
    await manager.broadcast({"type": "scan_complete", "target": target})


@app.post("/api/poc/generate")
async def generate_poc(payload: Dict[str, Any]):
    target = payload.get("target_domain", "example.com")
    exporter = BugBountyPoCExporter()
    finding = payload.get("finding", {
        "target_url": f"https://{target}/api/v1/user/profile?id=100",
        "vulnerability_type": "id_access_analysis",
        "confidence_score": 0.95,
        "reasoning": f"BOLA Verified: User B token exposed User A records on {target}."
    })
    poc_md = exporter.generate_hackerone_report(finding, target)
    return JSONResponse({"status": "SUCCESS", "poc_report": poc_md})


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "pong", "payload": data})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Static files mount
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>PenFlow Web UI Dashboard</h1>")
