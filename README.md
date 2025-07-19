# Praesidium NVR

Praesidium NVR is an enterprise network video recorder built with the .NET 8 SDK. It records and serves RTSP streams using FFmpeg and exposes a web interface from the `wwwroot` folder. Configuration is loaded from `/etc/nvr/config.json` with sensible defaults when the file is missing.

## Prerequisites

- .NET 8 SDK
- FFmpeg available on the system `PATH`
- (optional) SQLite is used automatically for authentication when enabled

## Building and Running

From the repository root run:

```bash
dotnet restore
dotnet build
dotnet run
```

The service listens on port 8080 by default. Customize settings in `/etc/nvr/config.json` as needed.

## Optional Authentication

Authentication is disabled by default. Set `RequireAuthentication: true` in the configuration file to enable JWT based login. When enabled, the default credentials are `admin/admin123!` (change immediately). The console output on startup reflects the current authentication mode.


