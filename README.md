# Praesidium NVR

This repository provides a modular network video recorder (NVR) written in Python. The goal is to build the project in a way that allows each feature to evolve independently while maintaining a simple core.

## Project layout

```
src/
    api/            # Interfaces for web APIs or external integrations
    configuration/  # Configuration loading and management
    storage/        # Video storage backends
    video_capture/  # Camera handling and frame capture
    main.py         # Application entry point
```

Each package exposes minimal interfaces so implementations can be replaced without affecting other modules.

## Development setup

1. **Python version**: 3.11 or newer is recommended.
2. **Virtual environment** (optional but encouraged):

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
3. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

## Running

To start the application:

```bash
python -m src.main
```

This will load the default configuration and start the placeholder API server.

## Web interface

Running the application starts a small Flask server on port `8000`. The index page now includes fields for a camera ID and RTSP URL. Submitting the form begins recording the stream under `recordings/<cam_id>/YEAR/MONTH/DAY/HOUR` in 30‑second MP4 segments. Each stream is recorded in a separate background thread with automatic reconnection if the connection drops.

The **Cameras** tab lists all added cameras and displays whether each one is currently recording or stopped. Clicking a camera ID opens a page where you can update the stream URL or start/stop recording.
