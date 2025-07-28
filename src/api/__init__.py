"""API module exposing a minimal web interface for adding RTSP streams."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, redirect, render_template_string, request, url_for

from ..recorder import StreamRecorder


INDEX_HTML = """
<!doctype html>
<title>Praesidium NVR</title>
<h1>Add RTSP Stream</h1>
<form method="post" action="/add">
  <input type="text" name="cam_id" placeholder="camera id" required />
  <input type="text" name="url" placeholder="rtsp://..." style="width: 300px;" />
  <input type="submit" value="Start Recording" />
</form>
"""


def start_server(config: Any) -> None:
    """Start the Flask server allowing manual RTSP input."""

    app = Flask(__name__)
    recorders: list[StreamRecorder] = []

    @app.route("/")
    def index() -> str:
        return render_template_string(INDEX_HTML)

    @app.route("/add", methods=["POST"])
    def add() -> Any:
        url = request.form.get("url")
        cam_id = request.form.get("cam_id")
        if url and cam_id:
            recorder = StreamRecorder(url, Path(config.storage_path), cam_id)
            recorder.start()
            recorders.append(recorder)
        return redirect(url_for("index"))

    app.run(host="0.0.0.0", port=8000)
