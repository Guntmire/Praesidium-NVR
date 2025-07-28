"""API module exposing a minimal web interface for adding and managing RTSP streams."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from flask import Flask, redirect, render_template_string, request, url_for

from ..recorder import StreamRecorder

INDEX_HTML = """
<!doctype html>
<title>Praesidium NVR</title>
<ul>
  <li><a href="/">Add Stream</a></li>
  <li><a href="/cameras">Cameras</a></li>
</ul>
<h1>Add RTSP Stream</h1>
<form method="post" action="/add">
  <input type="text" name="cam_id" placeholder="camera id" required />
  <input type="text" name="url" placeholder="rtsp://..." style="width: 300px;" />
  <input type="submit" value="Start Recording" />
</form>
"""

CAMERAS_HTML = """
<!doctype html>
<title>Praesidium NVR</title>
<ul>
  <li><a href="/">Add Stream</a></li>
  <li><a href="/cameras">Cameras</a></li>
</ul>
<h1>Existing Cameras</h1>
<ul>
{% for cam_id, rec in recorders.items() %}
  <li><a href="/camera/{{ cam_id }}">{{ cam_id }}</a> - {{ "recording" if rec.active else "stopped" }}</li>
{% endfor %}
</ul>
"""

EDIT_HTML = """
<!doctype html>
<title>Edit Camera {{ cam_id }}</title>
<ul>
  <li><a href="/">Add Stream</a></li>
  <li><a href="/cameras">Cameras</a></li>
</ul>
<h1>Edit Camera {{ cam_id }}</h1>
<form method="post">
  <input type="text" name="url" value="{{ url }}" style="width: 300px;" />
  {% if recorder.active %}
    <input type="submit" name="action" value="Stop" />
  {% else %}
    <input type="submit" name="action" value="Start" />
  {% endif %}
</form>
"""

def start_server(config: Any) -> None:
    """Start the Flask server allowing manual RTSP input."""

    app = Flask(__name__)
    # Keep a mapping of camera ID to its recorder so we can manage them
    recorders: Dict[str, StreamRecorder] = {}

    @app.route("/")
    def index() -> str:
        return render_template_string(INDEX_HTML)

    @app.route("/cameras")
    def cameras() -> str:
        return render_template_string(CAMERAS_HTML, recorders=recorders)

    @app.route("/add", methods=["POST"])
    def add() -> Any:
        url = request.form.get("url")
        cam_id = request.form.get("cam_id")
        if url and cam_id:
            # replace any existing recorder with same ID
            if cam_id in recorders:
                recorders[cam_id].stop()
            recorder = StreamRecorder(url, Path(config.storage_path), cam_id)
            recorder.start()
            recorders[cam_id] = recorder
        return redirect(url_for("cameras"))

    @app.route("/camera/<cam_id>", methods=["GET", "POST"])
    def edit_camera(cam_id: str) -> Any:
        recorder = recorders.get(cam_id)
        if not recorder:
            return redirect(url_for("cameras"))

        if request.method == "POST":
            url = request.form.get("url") or recorder.url
            action = request.form.get("action")
            if action == "Stop":
                recorder.stop()
            elif action == "Start":
                if recorder.active:
                    recorder.stop()
                recorder.url = url
                recorder.start()
            else:
                # just updating URL
                recorder.url = url
            return redirect(url_for("edit_camera", cam_id=cam_id))

        return render_template_string(
            EDIT_HTML,
            cam_id=cam_id,
            url=recorder.url,
            recorder=recorder,
        )

    app.run(host="0.0.0.0", port=8000)
