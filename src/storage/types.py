from pathlib import Path


class StorageTarget:
    """Represents a storage destination."""

    def __init__(self, path: Path):
        self.path = path
