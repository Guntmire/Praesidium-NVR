"""Video capture module.

This module provides classes and utilities for capturing video frames from
connected cameras. It can be extended to support different capture
technologies or libraries such as OpenCV.
"""

from typing import Iterator


class Frame:
    """Simple video frame container."""

    def __init__(self, data: bytes, timestamp: float):
        self.data = data
        self.timestamp = timestamp


class Camera:
    """Base camera interface."""

    def start(self) -> None:
        """Initialize camera and start capturing."""

    def stop(self) -> None:
        """Stop capturing and release resources."""

    def frames(self) -> Iterator[Frame]:
        """Yield captured frames as an iterator."""
        yield from ()
