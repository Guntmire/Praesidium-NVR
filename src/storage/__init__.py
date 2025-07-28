"""Storage module for persisting video frames or streams."""

from pathlib import Path
from .types import StorageTarget


class FileStorage:
    """Store frames to disk under a directory."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def store_frame(self, frame_data: bytes, filename: str) -> Path:
        target = self.directory / filename
        target.write_bytes(frame_data)
        return target


class StorageTarget:
    """Placeholder type for storage location information."""

    def __init__(self, path: Path):
        self.path = path
