# Praesidium NVR

Praesidium NVR is an enterprise network video recorder built with the .NET 8 SDK. It records and serves RTSP streams using FFmpeg and exposes a web interface from the `wwwroot` folder. Configuration is loaded from `/etc/nvr/config.json` with sensible defaults when the file is missing or empty.

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

Authentication is now enabled by default. To disable it, set `RequireAuthentication: false` in the configuration file. When enabled, the default credentials are `admin/admin123!` (change immediately). The console output on startup reflects the current authentication mode.



## Web Interface

The UI is implemented as a single HTML page (`wwwroot/index.html`). The tab bar and panels, including the **Storage** tab, are sections in this file that are toggled with JavaScript. Clicking a tab simply reveals its panel without leaving the page.

If `RequireAuthentication` is set to `false` in the configuration, these static pages can be opened directly. API endpoints still enforce authentication whenever it is enabled. The check is handled by middleware in `Program.cs`.

