import asyncio
import json
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, Response, request, jsonify, send_from_directory, abort
from werkzeug.serving import run_simple

import sys
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from penflow.core.orchestrator import Orchestrator
from penflow.core.event_bus import EventBus
from penflow.utils.file_utils import get_scan_dir
from penflow.config import Config

app = Flask(__name__)
event_bus = EventBus.get_instance()

# Global state to track events for the SSE stream
_latest_events = []
_active_scans = {}

_event_counter = 0

# We need an async to sync bridge for events
async def _event_listener(event):
    global _event_counter
    data = json.dumps({"type": event.type, "data": event.data})
    _latest_events.append((_event_counter, f"data: {data}\n\n"))
    _event_counter += 1
    if len(_latest_events) > 100:
        _latest_events.pop(0)

async def _register_bus():
    await event_bus.subscribe("*", _event_listener)

# Run the bus registration in a background thread
def setup_bus():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(_register_bus())
    loop.run_forever()

threading.Thread(target=setup_bus, daemon=True).start()

@app.route("/")
def dashboard():
    return render_template("dashboard.html", active_scans=_active_scans)

@app.route("/scan/new", methods=["GET", "POST"])
def new_scan():
    if request.method == "POST":
        target = request.form.get("target")
        if target:
            # Start scan in background thread
            def run_scan():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                orch = Orchestrator(target)
                _active_scans[target] = "running"
                try:
                    loop.run_until_complete(orch.run())
                    _active_scans[target] = "completed"
                except Exception as e:
                    _active_scans[target] = f"failed: {e}"
                    
            threading.Thread(target=run_scan, daemon=True).start()
            return render_template("scan_progress.html", target=target)
            
    return render_template("new_scan.html")

@app.route("/stream")
def stream():
    def event_stream():
        last_processed = _event_counter
        # Yield history from the current buffer so UI doesn't start completely blank
        for count, event in list(_latest_events):
            yield event
            last_processed = count + 1
            
        while True:
            current_events = list(_latest_events)
            for count, event in current_events:
                if count >= last_processed:
                    yield event
                    last_processed = count + 1
            import time
            time.sleep(0.5)
            
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/reports")
def list_reports():
    config = Config.load()
    scans_dir = Path(config.get("scans.directory", "scans"))
    reports = []
    
    if scans_dir.exists():
        for target_dir in scans_dir.iterdir():
            if target_dir.is_dir():
                target_name = target_dir.name
                for file in target_dir.iterdir():
                    if file.is_file() and file.suffix in ('.html', '.md'):
                        if file.name.startswith("report_"):
                            reports.append({
                                "target": target_name,
                                "filename": file.name,
                                "type": file.suffix[1:].upper(),
                                "size_kb": round(file.stat().st_size / 1024, 1),
                                "created": datetime.fromtimestamp(file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                            })
                            
    reports.sort(key=lambda x: x["created"], reverse=True)
    return render_template("reports_list.html", reports=reports)

@app.route("/reports/view/<target>/<filename>")
def view_report(target, filename):
    config = Config.load()
    scans_dir = Path(config.get("scans.directory", "scans"))
    target_dir = scans_dir / target
    file_path = target_dir / filename
    
    if not file_path.exists() or not file_path.is_file():
        abort(404)
        
    if filename.endswith(".html"):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    elif filename.endswith(".md"):
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        import markdown
        html_body = markdown.markdown(content, extensions=['tables', 'fenced_code'])
        return render_template("view_markdown.html", target=target, html_body=html_body, filename=filename)
    else:
        abort(400)

@app.route("/reports/download/<target>/<filename>")
def download_report(target, filename):
    config = Config.load()
    scans_dir = Path(config.get("scans.directory", "scans"))
    target_dir = scans_dir / target
    
    if not (target_dir / filename).exists():
        abort(404)
        
    return send_from_directory(directory=target_dir, path=filename, as_attachment=True)

if __name__ == "__main__":
    print("Starting PenFlow UI on http://localhost:5000")
    run_simple("0.0.0.0", 5000, app, use_reloader=True, use_debugger=False, threaded=True)
