"""Stream recording utilities using OpenCV."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

import cv2


class StreamRecorder:
    """Record an RTSP stream to disk with basic reconnection logic."""

    def __init__(self, url: str, output_dir: Path):
        self.url = url
        self.output_dir = output_dir
        self.active = False
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start recording in a background thread."""
        if self.active:
            return
        self.active = True
        self.thread = threading.Thread(target=self._record_loop, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Stop recording and wait for the thread to finish."""
        self.active = False
        if self.thread:
            self.thread.join()

    def _record_loop(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        while self.active:
            cap = cv2.VideoCapture(self.url)
            if not cap.isOpened():
                print(f"Failed to open {self.url}, retrying...")
                cap.release()
                time.sleep(2)
                continue

            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)) or 640
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)) or 480
            fps = cap.get(cv2.CAP_PROP_FPS) or 20.0

            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            file_path = self.output_dir / f"recording_{int(time.time())}.mp4"
            writer = cv2.VideoWriter(str(file_path), fourcc, fps, (width, height))

            while self.active:
                ret, frame = cap.read()
                if not ret:
                    print("Stream interrupted, attempting to reconnect...")
                    break
                writer.write(frame)

            writer.release()
            cap.release()
            time.sleep(2)
