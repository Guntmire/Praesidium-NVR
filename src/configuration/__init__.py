"""Configuration utilities for NVR."""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class NVRConfig:
    storage_path: Path
    camera_sources: list[str]


def load_default() -> NVRConfig:
    """Load default configuration."""
    return NVRConfig(storage_path=Path("./recordings"), camera_sources=[])
