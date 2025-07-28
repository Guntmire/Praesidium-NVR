"""Stream recording utilities using OpenCV."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import cv2


class StreamRecorder:
    """Record an RTSP stream to disk with basic reconnection logic."""

    def __init__(self, url: str, base_dir: Path, cam_id: str, segment_seconds: int = 30):
        self.url = url
        self.base_dir = base_dir
        self.cam_id = cam_id
        self.segment_seconds = segment_seconds
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
        self.base_dir.mkdir(parents=True, exist_ok=True)
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
            writer: Optional[cv2.VideoWriter] = None
            segment_start = time.time()

            while self.active:
                ret, frame = cap.read()
                if not ret:
                    print("Stream interrupted, attempting to reconnect...")
                    break

                if writer is None:
                    file_path = self._segment_path(segment_start)
                    writer = cv2.VideoWriter(str(file_path), fourcc, fps, (width, height))

                writer.write(frame)

                if time.time() - segment_start >= self.segment_seconds:
                    writer.release()
                    writer = None
                    segment_start = time.time()

            if writer is not None:
                writer.release()
            cap.release()
            time.sleep(2)

    def _segment_path(self, timestamp: float) -> Path:
        dt = datetime.fromtimestamp(timestamp)
        directory = (self.base_dir / self.cam_id /
                     dt.strftime("%Y/%m/%d/%H"))
        directory.mkdir(parents=True, exist_ok=True)
        filename = dt.strftime("%Y%m%d_%H%M%S.mp4")
        return directory / filename
