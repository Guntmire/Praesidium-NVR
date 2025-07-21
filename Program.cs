using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using Microsoft.Data.Sqlite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Net;
using Microsoft.Extensions.Configuration;

namespace EnterpriseNVR
{
    // Enhanced Configuration Models
    public class NvrConfig
    {
        public List<CameraConfig> Cameras { get; set; } = new();
        public string StorageBasePath { get; set; } = "/var/nvr";
        public int WebPort { get; set; } = 8080;
        public bool EnableHttps { get; set; } = false;
        public int MaxRetries { get; set; } = 5;
        public int RetryDelaySeconds { get; set; } = 30;
        public int MaxConcurrentStreams { get; set; } = 16;
        public string EncryptionKey { get; set; } = string.Empty;
        public int SessionTimeoutMinutes { get; set; } = 60;
        public int MaxLoginAttempts { get; set; } = 3;
        public int LoginLockoutMinutes { get; set; } = 15;
        public bool EnableAuditLog { get; set; } = true;
        public string[] AllowedNetworks { get; set; } = { "127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" };
        public string JwtSecret { get; set; } = string.Empty;
        public bool RequireAuthentication { get; set; } = true; // Enabled by default for improved security
        public EmailConfig EmailConfig { get; set; } = new();
    }

    public class EmailConfig
    {
        public string SmtpServer { get; set; } = string.Empty;
        public int SmtpPort { get; set; } = 587;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool EnableSsl { get; set; } = true;
        public string FromAddress { get; set; } = string.Empty;
    }

    public class CameraConfig
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = string.Empty;
        public string RtspUrl { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool Enabled { get; set; } = true;
        public int RecordingDays { get; set; } = 30;
        public string StoragePoolId { get; set; } = string.Empty;
        public bool EncryptStorage { get; set; } = true;
        public int SegmentSeconds { get; set; } = 3600;
        public string[] AllowedUsers { get; set; } = Array.Empty<string>();
        public string TimeZone { get; set; } = "UTC";
        public bool EnableMotionDetection { get; set; } = false;
        public bool EnableAlerts { get; set; } = false;
        public string[] AlertEmails { get; set; } = Array.Empty<string>();
    }

    // User Management Models
    public class User
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string[] Roles { get; set; } = Array.Empty<string>();
        public string[] AllowedCameras { get; set; } = Array.Empty<string>();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastLogin { get; set; }
        public bool IsActive { get; set; } = true;
        public string Email { get; set; } = string.Empty;
    }

    public class LoginRequest
    {
        [Required]
        public string Username { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
    }

    public class LoginResponse
    {
        public string Token { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public User User { get; set; } = new();
    }

    // Stream Status
    public enum StreamStatus
    {
        Stopped,
        Starting,
        Running,
        Failed,
        Reconnecting
    }

    public class CameraStreamInfo
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public StreamStatus Status { get; set; }
        public DateTime LastUpdate { get; set; }
        public string CurrentFile { get; set; } = string.Empty;
        public int RetryCount { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public bool MotionDetected { get; set; } = false;
        public DateTime LastMotionEvent { get; set; }
    }

    // Storage Management
    public class StoragePool
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = string.Empty;
        public List<string> MountPoints { get; set; } = new();
        public long TotalSpace { get; set; }
        public long FreeSpace { get; set; }
        public bool IsHealthy { get; set; } = true;
        public DateTime LastChecked { get; set; } = DateTime.UtcNow;
    }

    public class StorageManager
    {
        private readonly ILogger<StorageManager> _logger;
        private readonly List<StoragePool> _pools = new();
        private readonly string _emergencyPath = "/emergency_storage";

        public StorageManager(ILogger<StorageManager> logger)
        {
            _logger = logger;
            DiscoverStoragePools();
        }

        private void DiscoverStoragePools()
        {
            try
            {
                var mountPoints = Directory.GetDirectories("/", "nvr_storage*", SearchOption.TopDirectoryOnly);
                
                foreach (var mountPoint in mountPoints)
                {
                    if (Directory.Exists(mountPoint))
                    {
                        var driveInfo = new DriveInfo(mountPoint);
                        var pool = new StoragePool
                        {
                            Name = Path.GetFileName(mountPoint),
                            MountPoints = new List<string> { mountPoint },
                            TotalSpace = driveInfo.TotalSize,
                            FreeSpace = driveInfo.AvailableFreeSpace,
                            IsHealthy = driveInfo.IsReady
                        };
                        
                        _pools.Add(pool);
                        _logger.LogInformation($"Discovered storage pool: {pool.Name} at {mountPoint}");
                    }
                }

                if (_pools.Count == 0)
                {
                    _logger.LogWarning("No nvr_storage* mounts found, using emergency storage");
                    
                    try
                    {
                        Directory.CreateDirectory(_emergencyPath);
                        var driveInfo = new DriveInfo("/");
                        var emergencyPool = new StoragePool
                        {
                            Name = "Emergency Storage",
                            MountPoints = new List<string> { _emergencyPath },
                            TotalSpace = driveInfo.TotalSize,
                            FreeSpace = driveInfo.AvailableFreeSpace,
                            IsHealthy = driveInfo.IsReady
                        };
                        _pools.Add(emergencyPool);
                        _logger.LogInformation("Added emergency storage pool");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Error creating emergency storage: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error discovering storage pools: {ex.Message}");
            }
        }

        public List<StoragePool> GetStoragePools() => _pools;

        public void UpdatePoolHealth()
        {
            foreach (var pool in _pools)
            {
                try
                {
                    var driveInfo = new DriveInfo(pool.MountPoints.First());
                    pool.TotalSpace = driveInfo.TotalSize;
                    pool.FreeSpace = driveInfo.AvailableFreeSpace;
                    pool.IsHealthy = driveInfo.IsReady && driveInfo.AvailableFreeSpace > 1024 * 1024 * 1024; // 1GB minimum
                    pool.LastChecked = DateTime.UtcNow;
                }
                catch (Exception ex)
                {
                    pool.IsHealthy = false;
                    _logger.LogError($"Error checking pool health {pool.Name}: {ex.Message}");
                }
            }
        }

        public string GetStoragePath(string poolId, string cameraId, DateTime timestamp)
        {
            var pool = _pools.FirstOrDefault(p => p.Id == poolId);
            if (pool == null || !pool.IsHealthy)
            {
                _logger.LogWarning($"Storage pool {poolId} not available, using emergency storage");
                return GetEmergencyPath(cameraId, timestamp);
            }

            var mountPoint = pool.MountPoints.First();
            return Path.Combine(mountPoint, cameraId, 
                timestamp.ToString("yyyy"), 
                timestamp.ToString("MM"), 
                timestamp.ToString("dd"));
        }

        private string GetEmergencyPath(string cameraId, DateTime timestamp)
        {
            return Path.Combine(_emergencyPath, cameraId, 
                timestamp.ToString("yyyy"), 
                timestamp.ToString("MM"), 
                timestamp.ToString("dd"));
        }
    }

    // Database Service for Enhanced Features
    public partial class DatabaseService
    {
        private readonly string _connectionString;
        private readonly ILogger<DatabaseService> _logger;

        public DatabaseService(ILogger<DatabaseService> logger, NvrConfig config)
        {
            _logger = logger;
            var dbPath = Path.Combine(config.StorageBasePath, "nvr.db");
            // Microsoft.Data.Sqlite does not support the "Version" keyword, so
            // we only specify the data source path
            _connectionString = $"Data Source={dbPath}";
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_connectionString.Split('=')[1].Split(';')[0])!);
                
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                var createTables = @"
                    CREATE TABLE IF NOT EXISTS Users (
                        Id TEXT PRIMARY KEY,
                        Username TEXT UNIQUE NOT NULL,
                        PasswordHash TEXT NOT NULL,
                        Roles TEXT NOT NULL,
                        AllowedCameras TEXT NOT NULL,
                        CreatedAt TEXT NOT NULL,
                        LastLogin TEXT,
                        IsActive INTEGER NOT NULL,
                        Email TEXT
                    );

                    CREATE TABLE IF NOT EXISTS Recordings (
                        Id TEXT PRIMARY KEY,
                        CameraId TEXT NOT NULL,
                        CameraName TEXT NOT NULL,
                        StartTime TEXT NOT NULL,
                        EndTime TEXT,
                        FilePath TEXT NOT NULL,
                        FileSize INTEGER NOT NULL,
                        Duration INTEGER,
                        IsEncrypted INTEGER NOT NULL,
                        CreatedAt TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS Events (
                        Id TEXT PRIMARY KEY,
                        CameraId TEXT NOT NULL,
                        EventType TEXT NOT NULL,
                        Timestamp TEXT NOT NULL,
                        Description TEXT,
                        Severity TEXT NOT NULL,
                        Data TEXT
                    );

                    CREATE TABLE IF NOT EXISTS AuditLog (
                        Id TEXT PRIMARY KEY,
                        UserId TEXT NOT NULL,
                        Action TEXT NOT NULL,
                        Target TEXT,
                        Timestamp TEXT NOT NULL,
                        IpAddress TEXT,
                        UserAgent TEXT,
                        Success INTEGER NOT NULL,
                        Details TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_recordings_camera_time ON Recordings(CameraId, StartTime);
                    CREATE INDEX IF NOT EXISTS idx_events_camera_time ON Events(CameraId, Timestamp);
                    CREATE INDEX IF NOT EXISTS idx_audit_user_time ON AuditLog(UserId, Timestamp);
                ";

                using var command = new SqliteCommand(createTables, connection);
                command.ExecuteNonQuery();

                CreateDefaultUserIfNeeded(connection);
                
                _logger.LogInformation("Database initialized successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to initialize database: {ex.Message}");
                throw;
            }
        }

        private void CreateDefaultUserIfNeeded(SqliteConnection connection)
        {
            const string checkQuery = "SELECT COUNT(*) FROM Users WHERE Username = 'admin'";
            using var checkCommand = new SqliteCommand(checkQuery, connection);
            var userExists = Convert.ToInt32(checkCommand.ExecuteScalar()) > 0;

            if (!userExists)
            {
                var adminUser = new User
                {
                    Username = "admin",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin123!"),
                    Roles = new[] { "Administrator" },
                    AllowedCameras = Array.Empty<string>(),
                    Email = "admin@nvr.local"
                };

                CreateUser(adminUser);
                _logger.LogWarning("Created default admin user (admin/admin123!) - CHANGE PASSWORD IMMEDIATELY");
            }
        }

        public void CreateUser(User user)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            const string query = @"
                INSERT INTO Users (Id, Username, PasswordHash, Roles, AllowedCameras, CreatedAt, LastLogin, IsActive, Email)
                VALUES (@Id, @Username, @PasswordHash, @Roles, @AllowedCameras, @CreatedAt, @LastLogin, @IsActive, @Email)";

            using var command = new SqliteCommand(query, connection);
            command.Parameters.AddWithValue("@Id", user.Id);
            command.Parameters.AddWithValue("@Username", user.Username);
            command.Parameters.AddWithValue("@PasswordHash", user.PasswordHash);
            command.Parameters.AddWithValue("@Roles", JsonSerializer.Serialize(user.Roles));
            command.Parameters.AddWithValue("@AllowedCameras", JsonSerializer.Serialize(user.AllowedCameras));
            command.Parameters.AddWithValue("@CreatedAt", user.CreatedAt.ToString("O"));
            command.Parameters.AddWithValue("@LastLogin", user.LastLogin.ToString("O"));
            command.Parameters.AddWithValue("@IsActive", user.IsActive ? 1 : 0);
            command.Parameters.AddWithValue("@Email", user.Email);

            command.ExecuteNonQuery();
        }

        public User? GetUserByUsername(string username)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            const string query = "SELECT * FROM Users WHERE Username = @Username AND IsActive = 1";
            using var command = new SqliteCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);

            using var reader = command.ExecuteReader();
            if (reader.Read())
            {
                return new User
                {
                    Id = reader.GetString("Id"),
                    Username = reader.GetString("Username"),
                    PasswordHash = reader.GetString("PasswordHash"),
                    Roles = JsonSerializer.Deserialize<string[]>(reader.GetString("Roles")) ?? Array.Empty<string>(),
                    AllowedCameras = JsonSerializer.Deserialize<string[]>(reader.GetString("AllowedCameras")) ?? Array.Empty<string>(),
                    CreatedAt = DateTime.Parse(reader.GetString("CreatedAt")),
                    LastLogin = DateTime.Parse(reader.GetString("LastLogin")),
                    IsActive = reader.GetInt32("IsActive") == 1,
                    Email = reader.GetString("Email")
                };
            }

            return null;
        }

        public void UpdateUserLastLogin(string userId)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            const string query = "UPDATE Users SET LastLogin = @LastLogin WHERE Id = @Id";
            using var command = new SqliteCommand(query, connection);
            command.Parameters.AddWithValue("@LastLogin", DateTime.UtcNow.ToString("O"));
            command.Parameters.AddWithValue("@Id", userId);

            command.ExecuteNonQuery();
        }

        public void LogEvent(string cameraId, string eventType, string description, string severity = "Info", object? data = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                const string query = @"
                    INSERT INTO Events (Id, CameraId, EventType, Timestamp, Description, Severity, Data)
                    VALUES (@Id, @CameraId, @EventType, @Timestamp, @Description, @Severity, @Data)";

                using var command = new SqliteCommand(query, connection);
                command.Parameters.AddWithValue("@Id", Guid.NewGuid().ToString());
                command.Parameters.AddWithValue("@CameraId", cameraId);
                command.Parameters.AddWithValue("@EventType", eventType);
                command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow.ToString("O"));
                command.Parameters.AddWithValue("@Description", description);
                command.Parameters.AddWithValue("@Severity", severity);
                command.Parameters.AddWithValue("@Data", data != null ? JsonSerializer.Serialize(data) : "");

                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to log event: {ex.Message}");
            }
        }

        public void LogAudit(string userId, string action, string target, string ipAddress, string userAgent, bool success, object? details = null)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                const string query = @"
                    INSERT INTO AuditLog (Id, UserId, Action, Target, Timestamp, IpAddress, UserAgent, Success, Details)
                    VALUES (@Id, @UserId, @Action, @Target, @Timestamp, @IpAddress, @UserAgent, @Success, @Details)";

                using var command = new SqliteCommand(query, connection);
                command.Parameters.AddWithValue("@Id", Guid.NewGuid().ToString());
                command.Parameters.AddWithValue("@UserId", userId);
                command.Parameters.AddWithValue("@Action", action);
                command.Parameters.AddWithValue("@Target", target ?? "");
                command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow.ToString("O"));
                command.Parameters.AddWithValue("@IpAddress", ipAddress);
                command.Parameters.AddWithValue("@UserAgent", userAgent);
                command.Parameters.AddWithValue("@Success", success ? 1 : 0);
                command.Parameters.AddWithValue("@Details", details != null ? JsonSerializer.Serialize(details) : "");

                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to log audit: {ex.Message}");
            }
        }

        public List<Dictionary<string, object>> SearchRecordings(string cameraId, DateTime startTime, DateTime endTime, int limit = 100)
        {
            var results = new List<Dictionary<string, object>>();

            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                const string query = @"
                    SELECT * FROM Recordings 
                    WHERE CameraId = @CameraId 
                    AND StartTime >= @StartTime 
                    AND StartTime <= @EndTime 
                    ORDER BY StartTime DESC 
                    LIMIT @Limit";

                using var command = new SqliteCommand(query, connection);
                command.Parameters.AddWithValue("@CameraId", cameraId);
                command.Parameters.AddWithValue("@StartTime", startTime.ToString("O"));
                command.Parameters.AddWithValue("@EndTime", endTime.ToString("O"));
                command.Parameters.AddWithValue("@Limit", limit);

                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    var record = new Dictionary<string, object>();
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        record[reader.GetName(i)] = reader.GetValue(i);
                    }
                    results.Add(record);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to search recordings: {ex.Message}");
            }

            return results;
        }

        public void LogRecording(string cameraId, string cameraName, string filePath, long fileSize, int duration = 0, bool isEncrypted = false)
        {
            try
            {
                using var connection = new SqliteConnection(_connectionString);
                connection.Open();

                const string query = @"
                    INSERT INTO Recordings (Id, CameraId, CameraName, StartTime, FilePath, FileSize, Duration, IsEncrypted, CreatedAt)
                    VALUES (@Id, @CameraId, @CameraName, @StartTime, @FilePath, @FileSize, @Duration, @IsEncrypted, @CreatedAt)";

                using var command = new SqliteCommand(query, connection);
                command.Parameters.AddWithValue("@Id", Guid.NewGuid().ToString());
                command.Parameters.AddWithValue("@CameraId", cameraId);
                command.Parameters.AddWithValue("@CameraName", cameraName);
                command.Parameters.AddWithValue("@StartTime", DateTime.UtcNow.ToString("O"));
                command.Parameters.AddWithValue("@FilePath", filePath);
                command.Parameters.AddWithValue("@FileSize", fileSize);
                command.Parameters.AddWithValue("@Duration", duration);
                command.Parameters.AddWithValue("@IsEncrypted", isEncrypted ? 1 : 0);
                command.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow.ToString("O"));

                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to log recording: {ex.Message}");
            }
        }
    }

    // Authentication Service
    public class AuthenticationService
    {
        private readonly DatabaseService _database;
        private readonly ILogger<AuthenticationService> _logger;
        private readonly string _jwtSecret;

        public AuthenticationService(DatabaseService database, ILogger<AuthenticationService> logger, NvrConfig config)
        {
            _database = database;
            _logger = logger;
            _jwtSecret = config.JwtSecret;
        }

        public LoginResponse? AuthenticateAsync(LoginRequest request, string ipAddress, string userAgent)
        {
            try
            {
                var user = _database.GetUserByUsername(request.Username);
                if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    _database.LogAudit("", "Login", request.Username, ipAddress, userAgent, false, "Invalid credentials");
                    return null;
                }

                _database.UpdateUserLastLogin(user.Id);
                _database.LogAudit(user.Id, "Login", request.Username, ipAddress, userAgent, true);

                var token = GenerateJwtToken(user);
                var refreshToken = Guid.NewGuid().ToString();

                return new LoginResponse
                {
                    Token = token,
                    RefreshToken = refreshToken,
                    ExpiresAt = DateTime.UtcNow.AddHours(8),
                    User = user
                };
            }
            catch (Exception ex)
            {
                _logger.LogError($"Authentication error: {ex.Message}");
                return null;
            }
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim("allowedCameras", JsonSerializer.Serialize(user.AllowedCameras))
                }.Concat(user.Roles.Select(role => new Claim(ClaimTypes.Role, role)))),
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    // Video Streaming Service
    public class VideoStreamingService
    {
        private readonly ILogger<VideoStreamingService> _logger;
        private readonly StorageManager _storageManager;
        private readonly ConcurrentDictionary<string, Process> _liveStreams = new();

        public VideoStreamingService(ILogger<VideoStreamingService> logger, StorageManager storageManager)
        {
            _logger = logger;
            _storageManager = storageManager;
        }

        public string StartLiveStreamAsync(CameraConfig camera)
        {
            var streamId = Guid.NewGuid().ToString("N")[..8];
            var outputPath = $"/tmp/live_{streamId}.m3u8";

            var rtspUrl = BuildRtspUrl(camera);
            var ffmpegArgs = $"-i \"$RTSP_URL\" " +
                            $"-c:v libx264 -preset ultrafast -tune zerolatency " +
                            $"-c:a aac -b:a 128k " +
                            $"-f hls -hls_time 2 -hls_list_size 3 -hls_flags delete_segments " +
                            $"-hls_segment_filename /tmp/live_{streamId}_%03d.ts " +
                            $"\"{outputPath}\"";

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "/bin/bash",
                    Arguments = $"-c \"exec ffmpeg {ffmpegArgs}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            process.StartInfo.EnvironmentVariables["RTSP_URL"] = rtspUrl;

            process.Start();
            _liveStreams.TryAdd(streamId, process);
            
            _logger.LogInformation($"Started live stream {streamId} for camera {camera.Name}");
            return streamId;
        }

        public void StopLiveStream(string streamId)
        {
            if (_liveStreams.TryRemove(streamId, out var process))
            {
                try
                {
                    process.Kill();
                    process.WaitForExit(2000);
                    process.Dispose();
                    
                    var files = Directory.GetFiles("/tmp", $"live_{streamId}*");
                    foreach (var file in files)
                    {
                        try { File.Delete(file); } catch { }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error stopping live stream {streamId}: {ex.Message}");
                }
            }
        }

        private string BuildRtspUrl(CameraConfig camera)
        {
            try
            {
                var uri = new Uri(camera.RtspUrl);
                
                if (!string.IsNullOrEmpty(camera.Username) && !string.IsNullOrEmpty(camera.Password))
                {
                    var encodedUsername = Uri.EscapeDataString(camera.Username);
                    var encodedPassword = Uri.EscapeDataString(camera.Password);
                    return $"{uri.Scheme}://{encodedUsername}:{encodedPassword}@{uri.Host}:{uri.Port}{uri.PathAndQuery}";
                }
                
                return camera.RtspUrl;
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Invalid RTSP URL: {ex.Message}");
            }
        }
    }

    // Enhanced System Metrics
    public class SystemMetrics
    {
        public double CpuUsage { get; set; }
        public long MemoryUsage { get; set; }
        public long TotalMemory { get; set; }
        public Dictionary<string, StoragePool> StoragePools { get; set; } = new();
        public Dictionary<string, CameraStreamInfo> ActiveStreams { get; set; } = new();
        public int TotalRecordings { get; set; }
        public long TotalStorageUsed { get; set; }
        public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
        public List<string> RecentErrors { get; set; } = new();
        public int MotionEventsToday { get; set; }
        public Dictionary<string, int> StreamStatusCounts { get; set; } = new();
    }

    public class MetricsCollector
    {
        private readonly ILogger<MetricsCollector> _logger;
        private readonly StorageManager _storageManager;
        private readonly RtspStreamManager _streamManager;
        private readonly DatabaseService? _database;

        public MetricsCollector(ILogger<MetricsCollector> logger, StorageManager storageManager, RtspStreamManager streamManager, DatabaseService? database = null)
        {
            _logger = logger;
            _storageManager = storageManager;
            _streamManager = streamManager;
            _database = database;
        }

        public async Task<SystemMetrics> CollectMetricsAsync()
        {
            var metrics = new SystemMetrics();

            try
            {
                _storageManager.UpdatePoolHealth();
                
                var pools = _storageManager.GetStoragePools();
                foreach (var pool in pools)
                {
                    metrics.StoragePools[pool.Id] = pool;
                }

                metrics.ActiveStreams = _streamManager.GetStreamInfo();
                
                // Count stream statuses
                foreach (var status in metrics.ActiveStreams.Values.Select(s => s.Status.ToString()))
                {
                    metrics.StreamStatusCounts[status] = metrics.StreamStatusCounts.GetValueOrDefault(status, 0) + 1;
                }

                // Enhanced metrics if database is available
                if (_database != null)
                {
                    // You can add database-based metrics here
                }

                metrics.CpuUsage = await GetCpuUsageAsync();
                metrics.MemoryUsage = GC.GetTotalMemory(false);
                metrics.TotalMemory = GetTotalMemory();
                metrics.LastUpdate = DateTime.UtcNow;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error collecting metrics: {ex.Message}");
                metrics.RecentErrors.Add(ex.Message);
            }

            return metrics;
        }

        private async Task<double> GetCpuUsageAsync()
        {
            try
            {
                var startTime = DateTime.UtcNow;
                var startCpuUsage = Process.GetCurrentProcess().TotalProcessorTime;
                
                await Task.Delay(1000);
                
                var endTime = DateTime.UtcNow;
                var endCpuUsage = Process.GetCurrentProcess().TotalProcessorTime;
                
                var cpuUsedMs = (endCpuUsage - startCpuUsage).TotalMilliseconds;
                var totalMsPassed = (endTime - startTime).TotalMilliseconds;
                
                return cpuUsedMs / (Environment.ProcessorCount * totalMsPassed) * 100;
            }
            catch
            {
                return 0;
            }
        }

        private long GetTotalMemory()
        {
            try
            {
                var memInfo = File.ReadAllText("/proc/meminfo");
                var match = Regex.Match(memInfo, @"MemTotal:\s+(\d+) kB");
                return match.Success ? long.Parse(match.Groups[1].Value) * 1024 : 0;
            }
            catch
            {
                return 0;
            }
        }
    }

    // Enhanced Stream Manager
    public class RtspStreamManager
    {
        private readonly ILogger<RtspStreamManager> _logger;
        private readonly ConcurrentDictionary<string, CameraStreamInfo> _streamInfo = new();
        private readonly ConcurrentDictionary<string, Process> _ffmpegProcesses = new();
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _cancellationTokens = new();
        private readonly NvrConfig _config;
        private readonly StorageManager _storageManager;
        private readonly DatabaseService? _database;

        public RtspStreamManager(ILogger<RtspStreamManager> logger, NvrConfig config, StorageManager storageManager, DatabaseService? database = null)
        {
            _logger = logger;
            _config = config;
            _storageManager = storageManager;
            _database = database;
            
            _ = Task.Run(ConvertTsToMp4Async);
            _ = Task.Run(RetentionCleanupAsync);
        }

        public Task StartCameraAsync(CameraConfig camera)
        {
            if (_streamInfo.Count >= _config.MaxConcurrentStreams)
            {
                throw new InvalidOperationException("Maximum concurrent streams reached");
            }

            var info = new CameraStreamInfo
            {
                Id = camera.Id,
                Name = camera.Name,
                Status = StreamStatus.Starting,
                LastUpdate = DateTime.UtcNow
            };

            _streamInfo.AddOrUpdate(camera.Id, info, (key, oldInfo) => info);
            _logger.LogInformation($"Starting camera {camera.Name}");

            _database?.LogEvent(camera.Id, "StreamStart", $"Starting stream for camera {camera.Name}");

            var cts = new CancellationTokenSource();
            _cancellationTokens.AddOrUpdate(camera.Id, cts, (key, oldCts) => 
            {
                oldCts?.Cancel();
                return cts;
            });

            _ = Task.Run(async () => await ManageStreamAsync(camera, cts.Token));

            return Task.CompletedTask;
        }

        private async Task ManageStreamAsync(CameraConfig camera, CancellationToken cancellationToken)
        {
            var retryCount = 0;
            
            while (!cancellationToken.IsCancellationRequested && retryCount < _config.MaxRetries)
            {
                try
                {
                    await StartFFmpegProcessAsync(camera, cancellationToken);
                    retryCount = 0;
                }
                catch (Exception ex)
                {
                    retryCount++;
                    _logger.LogError($"Camera {camera.Name} failed (attempt {retryCount}): {ex.Message}");
                    
                    _database?.LogEvent(camera.Id, "StreamError", $"Stream failed: {ex.Message}", "Error");
                    UpdateStreamInfo(camera.Id, StreamStatus.Failed, errorMessage: ex.Message, retryCount: retryCount);
                    
                    if (retryCount < _config.MaxRetries)
                    {
                        UpdateStreamInfo(camera.Id, StreamStatus.Reconnecting, retryCount: retryCount);
                        await Task.Delay(TimeSpan.FromSeconds(_config.RetryDelaySeconds), cancellationToken);
                    }
                }
            }

            if (retryCount >= _config.MaxRetries)
            {
                _logger.LogError($"Camera {camera.Name} exceeded maximum retry attempts");
                _database?.LogEvent(camera.Id, "StreamFailed", "Maximum retry attempts exceeded", "Critical");
                UpdateStreamInfo(camera.Id, StreamStatus.Failed, errorMessage: "Maximum retry attempts exceeded");
            }
        }

        private async Task StartFFmpegProcessAsync(CameraConfig camera, CancellationToken cancellationToken)
        {
            var timestamp = DateTime.UtcNow;
            var localTime = ConvertToTimeZone(timestamp, camera.TimeZone);
            
            var outputDir = _storageManager.GetStoragePath(camera.StoragePoolId, camera.Id, localTime);
            var liveDir = Path.Combine(outputDir, "live");
            Directory.CreateDirectory(liveDir);

            var rtspUrl = BuildRtspUrl(camera);
            var segmentPattern = Path.Combine(liveDir, $"{localTime:yyyyMMdd}_%H%M%S.ts");
            var ffmpegArgs = BuildFFmpegArgs("$RTSP_URL", segmentPattern, camera.SegmentSeconds);

            var processInfo = new ProcessStartInfo
            {
                FileName = "/bin/bash",
                Arguments = $"-c \"exec ffmpeg {ffmpegArgs}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = liveDir
            };

            processInfo.EnvironmentVariables["RTSP_URL"] = rtspUrl;
            var process = new Process { StartInfo = processInfo };
            
            process.OutputDataReceived += (sender, e) => 
            {
                if (!string.IsNullOrEmpty(e.Data))
                    _logger.LogDebug($"FFmpeg stdout [{camera.Name}]: {e.Data}");
            };

            process.ErrorDataReceived += (sender, e) => 
            {
                if (!string.IsNullOrEmpty(e.Data) && !e.Data.Contains("deprecated") && !e.Data.Contains("Application provided invalid"))
                    _logger.LogDebug($"FFmpeg stderr [{camera.Name}]: {e.Data}");
            };

            _ffmpegProcesses.AddOrUpdate(camera.Id, process, (key, oldProcess) => 
            {
                try
                {
                    oldProcess?.Kill();
                    oldProcess?.WaitForExit(1000);
                }
                catch { }
                finally
                {
                    oldProcess?.Dispose();
                }
                return process;
            });

            try
            {
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                UpdateStreamInfo(camera.Id, StreamStatus.Running, currentFile: liveDir);
                _logger.LogInformation($"Started FFmpeg recording for camera {camera.Name} to {liveDir}");

                while (!process.HasExited && !cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(5000, cancellationToken);
                    UpdateStreamInfo(camera.Id, StreamStatus.Running, currentFile: liveDir);
                    
                    if (process.HasExited)
                        break;
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    _logger.LogInformation($"Stopping camera {camera.Name} - cancellation requested");
                    TerminateFFmpegProcess(process);
                    UpdateStreamInfo(camera.Id, StreamStatus.Stopped);
                }
                else if (process.HasExited)
                {
                    var exitCode = process.ExitCode;
                    if (exitCode != 0)
                    {
                        throw new Exception($"FFmpeg process exited unexpectedly with code {exitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                TerminateFFmpegProcess(process);
                throw new Exception($"Failed to start FFmpeg process: {ex.Message}", ex);
            }
        }

        private DateTime ConvertToTimeZone(DateTime utcTime, string timeZone)
        {
            try
            {
                if (string.IsNullOrEmpty(timeZone) || timeZone == "UTC")
                    return utcTime;
                
                var timeZoneInfo = TimeZoneInfo.FindSystemTimeZoneById(timeZone);
                return TimeZoneInfo.ConvertTimeFromUtc(utcTime, timeZoneInfo);
            }
            catch
            {
                return utcTime;
            }
        }

        private string BuildRtspUrl(CameraConfig camera)
        {
            try
            {
                var uri = new Uri(camera.RtspUrl);
                
                if (!string.IsNullOrEmpty(camera.Username) && !string.IsNullOrEmpty(camera.Password))
                {
                    var encodedUsername = Uri.EscapeDataString(camera.Username);
                    var encodedPassword = Uri.EscapeDataString(camera.Password);
                    return $"{uri.Scheme}://{encodedUsername}:{encodedPassword}@{uri.Host}:{uri.Port}{uri.PathAndQuery}";
                }
                
                return camera.RtspUrl;
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Invalid RTSP URL: {ex.Message}");
            }
        }

        private string BuildFFmpegArgs(string rtspUrl, string outputPattern, int segmentSeconds)
        {
            return $"-rtsp_transport tcp " +
                   $"-i \"{rtspUrl}\" " +
                   $"-c copy " +
                   $"-f segment " +
                   $"-segment_time {segmentSeconds} " +
                   $"-segment_format mpegts " +
                   $"-strftime 1 " +
                   $"-segment_wrap 168 " +
                   $"-reset_timestamps 1 " +
                   $"-avoid_negative_ts make_zero " +
                   $"\"{outputPattern}\"";
        }

        private void TerminateFFmpegProcess(Process process)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    process.WaitForExit(5000);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Error terminating FFmpeg process: {ex.Message}");
            }
            finally
            {
                process.Dispose();
            }
        }

        private async Task ConvertTsToMp4Async()
        {
            while (true)
            {
                try
                {
                    foreach (var camera in _config.Cameras)
                    {
                        await ProcessCameraFiles(camera);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error in TS to MP4 conversion: {ex.Message}");
                }

                await Task.Delay(TimeSpan.FromMinutes(5));
            }
        }

        private async Task ProcessCameraFiles(CameraConfig camera)
        {
            try
            {
                for (int i = 0; i < 7; i++)
                {
                    var checkDate = DateTime.UtcNow.AddDays(-i);
                    var basePath = _storageManager.GetStoragePath(camera.StoragePoolId, camera.Id, checkDate);
                    var liveDir = Path.Combine(basePath, "live");
                    var archiveDir = Path.Combine(basePath, "archive");

                    if (!Directory.Exists(liveDir)) continue;

                    Directory.CreateDirectory(archiveDir);

                    var tsFiles = Directory.GetFiles(liveDir, "*.ts")
                        .Where(f => File.GetLastWriteTime(f) < DateTime.UtcNow.AddMinutes(-5))
                        .OrderBy(f => File.GetCreationTime(f))
                        .ToArray();

                    foreach (var tsFile in tsFiles)
                    {
                        await ConvertTsToMp4(tsFile, archiveDir, camera.EncryptStorage, camera);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing files for camera {camera.Name}: {ex.Message}");
            }
        }

        private async Task ConvertTsToMp4(string tsFile, string archiveDir, bool encrypt, CameraConfig camera)
        {
            try
            {
                var fileName = Path.GetFileNameWithoutExtension(tsFile);
                var mp4File = Path.Combine(archiveDir, $"{fileName}.mp4");

                var args = $"-i \"{tsFile}\" -c copy -f mp4 -movflags +faststart \"{mp4File}\"";
                
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ffmpeg",
                        Arguments = args,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    }
                };

                process.Start();
                await process.WaitForExitAsync();

                if (process.ExitCode == 0)
                {
                    if (encrypt)
                    {
                        await EncryptFile(mp4File);
                    }
                    
                    File.Delete(tsFile);
                    
                    // Log recording to database
                    var fileInfo = new FileInfo(mp4File);
                    _database?.LogRecording(camera.Id, camera.Name, mp4File, fileInfo.Length, 0, encrypt);
                    
                    _logger.LogDebug($"Converted and archived: {Path.GetFileName(tsFile)} -> {Path.GetFileName(mp4File)}");
                }
                else
                {
                    _logger.LogWarning($"FFmpeg conversion failed for {tsFile} with exit code {process.ExitCode}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error converting {tsFile}: {ex.Message}");
            }
        }

        private async Task EncryptFile(string filePath)
        {
            if (string.IsNullOrEmpty(_config.EncryptionKey)) return;

            try
            {
                var data = await File.ReadAllBytesAsync(filePath);
                var encryptedData = EncryptData(data, _config.EncryptionKey);
                await File.WriteAllBytesAsync($"{filePath}.enc", encryptedData);
                File.Delete(filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error encrypting {filePath}: {ex.Message}");
            }
        }

        private byte[] EncryptData(byte[] data, string key)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            ms.Write(aes.IV);
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            cs.Write(data);
            cs.FlushFinalBlock();
            return ms.ToArray();
        }

        private async Task RetentionCleanupAsync()
        {
            while (true)
            {
                try
                {
                    foreach (var camera in _config.Cameras)
                    {
                        await CleanupExpiredFiles(camera);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error in retention cleanup: {ex.Message}");
                }

                await Task.Delay(TimeSpan.FromHours(1));
            }
        }

        private Task CleanupExpiredFiles(CameraConfig camera)
        {
            try
            {
                var cutoffDate = DateTime.UtcNow.AddDays(-camera.RecordingDays);
                
                for (var date = cutoffDate.AddDays(-7); date <= cutoffDate; date = date.AddDays(1))
                {
                    var basePath = _storageManager.GetStoragePath(camera.StoragePoolId, camera.Id, date);
                    
                    if (Directory.Exists(basePath))
                    {
                        var allFiles = Directory.GetFiles(basePath, "*.*", SearchOption.AllDirectories)
                            .Where(f => File.GetCreationTime(f) < cutoffDate);

                        foreach (var file in allFiles)
                        {
                            try
                            {
                                File.Delete(file);
                                _logger.LogInformation($"Deleted expired file: {file}");
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning($"Could not delete expired file {file}: {ex.Message}");
                            }
                        }

                        if (!Directory.EnumerateFileSystemEntries(basePath).Any())
                        {
                            Directory.Delete(basePath, true);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error cleaning up expired files for camera {camera.Name}: {ex.Message}");
            }

            return Task.CompletedTask;
        }

        public async Task StopCameraAsync(string cameraId)
        {
            _logger.LogInformation($"Stopping camera {cameraId}");
            
            if (_cancellationTokens.TryRemove(cameraId, out var cts))
            {
                cts.Cancel();
            }

            if (_ffmpegProcesses.TryRemove(cameraId, out var process))
            {
                TerminateFFmpegProcess(process);
            }

            _streamInfo.TryRemove(cameraId, out _);
            await Task.CompletedTask;
        }

        private void UpdateStreamInfo(string cameraId, StreamStatus status, string currentFile = "", string errorMessage = "", int retryCount = 0)
        {
            _streamInfo.AddOrUpdate(cameraId, 
                new CameraStreamInfo 
                { 
                    Id = cameraId, 
                    Status = status, 
                    LastUpdate = DateTime.UtcNow,
                    CurrentFile = currentFile,
                    ErrorMessage = errorMessage,
                    RetryCount = retryCount
                },
                (key, oldInfo) => 
                {
                    oldInfo.Status = status;
                    oldInfo.LastUpdate = DateTime.UtcNow;
                    if (!string.IsNullOrEmpty(currentFile)) oldInfo.CurrentFile = currentFile;
                    if (!string.IsNullOrEmpty(errorMessage)) oldInfo.ErrorMessage = errorMessage;
                    oldInfo.RetryCount = retryCount;
                    return oldInfo;
                });
        }

        public Dictionary<string, CameraStreamInfo> GetStreamInfo() => new(_streamInfo);
    }

    // Enhanced Configuration Manager
    public class ConfigurationManager
    {
        private readonly string _configPath;
        private readonly ILogger<ConfigurationManager> _logger;
        private NvrConfig _config = new();

        public ConfigurationManager(ILogger<ConfigurationManager> logger, string configPath = "/etc/nvr/config.json")
        {
            _logger = logger;
            _configPath = configPath;
            LoadConfiguration();
        }

        public NvrConfig GetConfiguration() => _config;

        public async Task SaveConfigurationAsync(NvrConfig config)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_configPath)!);
                var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_configPath, json);
                _config = config;
                _logger.LogInformation("Configuration saved successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to save configuration: {ex.Message}");
                throw;
            }
        }

        private void LoadConfiguration()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    var json = File.ReadAllText(_configPath);
                    _config = JsonSerializer.Deserialize<NvrConfig>(json) ?? new NvrConfig();
                }
                else
                {
                    _config = new NvrConfig();
                    _logger.LogWarning("Configuration file not found, using defaults");
                }

                if (string.IsNullOrEmpty(_config.EncryptionKey))
                {
                    _config.EncryptionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                    _logger.LogInformation("Generated new encryption key");
                }

                if (string.IsNullOrEmpty(_config.JwtSecret))
                {
                    _config.JwtSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                    _logger.LogInformation("Generated new JWT secret");
                }

                _ = Task.Run(async () => await SaveConfigurationAsync(_config));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to load configuration: {ex.Message}");
                _config = new NvrConfig();
                _config.EncryptionKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                _config.JwtSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            }
        }
    }

    // Optional Conditional Authentication Middleware
    public class ConditionalAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly NvrConfig _config;

        public ConditionalAuthenticationMiddleware(RequestDelegate next, NvrConfig config)
        {
            _next = next;
            _config = config;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Skip authentication if not required (backward compatibility)
            if (!_config.RequireAuthentication)
            {
                await _next(context);
                return;
            }

            // Apply authentication for protected endpoints
            var path = context.Request.Path.Value?.ToLower() ?? "";
            if (path.StartsWith("/api/") && !path.StartsWith("/api/auth/") && !path.StartsWith("/api/health"))
            {
                if (!context.User.Identity?.IsAuthenticated == true)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Authentication required");
                    return;
                }
            }

            await _next(context);
        }
    }

    // Enhanced NVR Controller with Optional Authentication
    [ApiController]
    [Route("api/[controller]")]
    public class NvrController : ControllerBase
    {
        private readonly ConfigurationManager _configManager;
        private readonly RtspStreamManager _streamManager;
        private readonly StorageManager _storageManager;
        private readonly MetricsCollector _metricsCollector;
        private readonly DatabaseService? _database;
        private readonly VideoStreamingService _videoService;
        private readonly ILogger<NvrController> _logger;

        public NvrController(ConfigurationManager configManager, RtspStreamManager streamManager, 
            StorageManager storageManager, MetricsCollector metricsCollector, ILogger<NvrController> logger,
            VideoStreamingService videoService, DatabaseService? database = null)
        {
            _configManager = configManager;
            _streamManager = streamManager;
            _storageManager = storageManager;
            _metricsCollector = metricsCollector;
            _videoService = videoService;
            _database = database;
            _logger = logger;
        }

        [HttpGet("config")]
        public IActionResult GetConfiguration()
        {
            return Ok(_configManager.GetConfiguration());
        }

        [HttpPost("config")]
        public async Task<IActionResult> SaveConfiguration([FromBody] NvrConfig config)
        {
            try
            {
                await _configManager.SaveConfigurationAsync(config);
                
                if (_database != null && User.Identity?.IsAuthenticated == true)
                {
                    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
                    
                    _database.LogAudit(userId, "ConfigUpdate", "System Configuration", ipAddress, userAgent, true);
                }
                
                return Ok(new { message = "Configuration saved successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPost("camera/{cameraId}/start")]
        public async Task<IActionResult> StartCamera(string cameraId)
        {
            var config = _configManager.GetConfiguration();
            var camera = config.Cameras.Find(c => c.Id == cameraId);
            
            if (camera == null)
                return NotFound(new { error = "Camera not found" });

            await _streamManager.StartCameraAsync(camera);
            
            if (_database != null && User.Identity?.IsAuthenticated == true)
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
                
                _database.LogAudit(userId, "StartCamera", camera.Name, ipAddress, userAgent, true);
            }
            
            return Ok(new { message = $"Camera {camera.Name} started" });
        }

        [HttpPost("camera/{cameraId}/stop")]
        public async Task<IActionResult> StopCamera(string cameraId)
        {
            await _streamManager.StopCameraAsync(cameraId);
            
            if (_database != null && User.Identity?.IsAuthenticated == true)
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
                
                _database.LogAudit(userId, "StopCamera", cameraId, ipAddress, userAgent, true);
            }
            
            return Ok(new { message = "Camera stopped" });
        }

        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            return Ok(_streamManager.GetStreamInfo());
        }

        [HttpGet("live/{cameraId}")]
        public IActionResult StartLiveView(string cameraId)
        {
            var config = _configManager.GetConfiguration();
            var camera = config.Cameras.Find(c => c.Id == cameraId);
            if (camera == null)
                return NotFound();

            var id = _videoService.StartLiveStreamAsync(camera);
            return Ok(new { streamId = id });
        }

        [HttpPost("live/{streamId}/stop")]
        public IActionResult StopLiveView(string streamId)
        {
            _videoService.StopLiveStream(streamId);
            return Ok();
        }

        [HttpGet("live/{streamId}/playlist")]
        public IActionResult LivePlaylist(string streamId)
        {
            var path = $"/tmp/live_{streamId}.m3u8";
            if (!System.IO.File.Exists(path)) return NotFound();
            return PhysicalFile(path, "application/vnd.apple.mpegurl");
        }

        [HttpGet("live/{streamId}/{segment}")]
        public IActionResult LiveSegment(string streamId, string segment)
        {
            var file = Path.GetFileName(segment);
            var path = $"/tmp/{file}";
            if (!System.IO.File.Exists(path)) return NotFound();
            return PhysicalFile(path, "video/MP2T");
        }

        [HttpGet("storage/pools")]
        public IActionResult GetStoragePools()
        {
            return Ok(_storageManager.GetStoragePools());
        }

        [HttpGet("metrics")]
        public async Task<IActionResult> GetSystemMetrics()
        {
            try
            {
                var metrics = await _metricsCollector.CollectMetricsAsync();
                return Ok(metrics);
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPost("cameras")]
        public async Task<IActionResult> AddCamera([FromBody] CameraConfig camera)
        {
            try
            {
                var config = _configManager.GetConfiguration();
                camera.Id = Guid.NewGuid().ToString();
                config.Cameras.Add(camera);
                await _configManager.SaveConfigurationAsync(config);
                
                if (_database != null && User.Identity?.IsAuthenticated == true)
                {
                    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
                    
                    _database.LogAudit(userId, "AddCamera", camera.Name, ipAddress, userAgent, true);
                }
                
                return Ok(new { message = "Camera added successfully", camera });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPut("cameras/{id}")]
        public async Task<IActionResult> UpdateCamera(string id, [FromBody] CameraConfig camera)
        {
            try
            {
                var config = _configManager.GetConfiguration();
                var existingCamera = config.Cameras.Find(c => c.Id == id);
                if (existingCamera == null)
                    return NotFound(new { error = "Camera not found" });

                camera.Id = id;
                var index = config.Cameras.IndexOf(existingCamera);
                config.Cameras[index] = camera;
                await _configManager.SaveConfigurationAsync(config);
                
                if (_database != null && User.Identity?.IsAuthenticated == true)
                {
                    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
                    
                    _database.LogAudit(userId, "UpdateCamera", camera.Name, ipAddress, userAgent, true);
                }
                
                return Ok(new { message = "Camera updated successfully", camera });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpDelete("cameras/{id}")]
        public async Task<IActionResult> DeleteCamera(string id)
        {
            try
            {
                var config = _configManager.GetConfiguration();
                var camera = config.Cameras.Find(c => c.Id == id);
                if (camera == null)
                    return NotFound(new { error = "Camera not found" });

                await _streamManager.StopCameraAsync(id);
                
                config.Cameras.Remove(camera);
                await _configManager.SaveConfigurationAsync(config);
                
                if (_database != null && User.Identity?.IsAuthenticated == true)
                {
                    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
                    
                    _database.LogAudit(userId, "DeleteCamera", camera.Name, ipAddress, userAgent, true);
                }
                
                return Ok(new { message = "Camera deleted successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpGet("cameras")]
        public IActionResult GetCameras()
        {
            var config = _configManager.GetConfiguration();
            return Ok(config.Cameras);
        }

        // New endpoints for enhanced features
        [HttpGet("recordings/{cameraId}")]
        public IActionResult GetRecordings(string cameraId, [FromQuery] DateTime? start, [FromQuery] DateTime? end, [FromQuery] int limit = 100)
        {
            if (_database == null)
                return BadRequest(new { error = "Database not available" });

            try
            {
                var startTime = start ?? DateTime.UtcNow.AddDays(-1);
                var endTime = end ?? DateTime.UtcNow;

                var recordings = _database.SearchRecordings(cameraId, startTime, endTime, limit);
                return Ok(recordings);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting recordings: {ex.Message}");
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpGet("playback")]
        public IActionResult PlayRecording([FromQuery] string path)
        {
            if (string.IsNullOrEmpty(path)) return BadRequest();
            var baseDir = Path.GetFullPath(_configManager.GetConfiguration().StorageBasePath);
            var fullPath = Path.GetFullPath(path);
            if (!fullPath.StartsWith(baseDir)) return BadRequest();
            if (!System.IO.File.Exists(fullPath)) return NotFound();
            return PhysicalFile(fullPath, "video/mp4", enableRangeProcessing: true);
        }
    }

    // Authentication Controller (Optional)
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthenticationService? _authService;
        private readonly DatabaseService? _database;
        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger, AuthenticationService? authService = null, DatabaseService? database = null)
        {
            _authService = authService;
            _database = database;
            _logger = logger;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            if (_authService == null)
                return BadRequest(new { error = "Authentication not enabled" });

            try
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var userAgent = HttpContext.Request.Headers.UserAgent.ToString();

                var response = _authService.AuthenticateAsync(request, ipAddress, userAgent);
                
                if (response == null)
                    return Unauthorized(new { error = "Invalid credentials" });

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Login error: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            if (_database != null && User.Identity?.IsAuthenticated == true)
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "";
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var userAgent = HttpContext.Request.Headers.UserAgent.ToString();

                _database.LogAudit(userId, "Logout", "", ipAddress, userAgent, true);
            }
            
            return Ok(new { message = "Logged out successfully" });
        }

        [HttpGet("user")]
        public IActionResult GetCurrentUser()
        {
            if (User.Identity?.IsAuthenticated != true)
                return Unauthorized();

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var username = User.FindFirst(ClaimTypes.Name)?.Value;
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();

            return Ok(new
            {
                id = userId,
                username,
                email,
                roles
            });
        }
    }

    // Health Controller
    [ApiController]
    [Route("api/[controller]")]
    public class HealthController : ControllerBase
    {
        private readonly StorageManager _storageManager;
        private readonly RtspStreamManager _streamManager;
        private readonly ILogger<HealthController> _logger;

        public HealthController(StorageManager storageManager, RtspStreamManager streamManager, ILogger<HealthController> logger)
        {
            _storageManager = storageManager;
            _streamManager = streamManager;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> GetHealth()
        {
            try
            {
                _storageManager.UpdatePoolHealth();
                var pools = _storageManager.GetStoragePools();
                var streams = _streamManager.GetStreamInfo();

                var ffmpegStatus = await CheckFFmpegAsync();

                var health = new
                {
                    timestamp = DateTime.UtcNow,
                    status = pools.Any(p => p.IsHealthy) && ffmpegStatus ? "healthy" : "unhealthy",
                    services = new
                    {
                        storage = new
                        {
                            status = pools.Any(p => p.IsHealthy) ? "healthy" : "unhealthy",
                            pools = pools.Count,
                            healthyPools = pools.Count(p => p.IsHealthy),
                            totalSpace = pools.Sum(p => p.TotalSpace),
                            freeSpace = pools.Sum(p => p.FreeSpace)
                        },
                        streams = new
                        {
                            status = "healthy",
                            totalStreams = streams.Count,
                            runningStreams = streams.Count(s => s.Value.Status == StreamStatus.Running),
                            failedStreams = streams.Count(s => s.Value.Status == StreamStatus.Failed)
                        },
                        ffmpeg = new
                        {
                            status = ffmpegStatus ? "available" : "unavailable"
                        }
                    }
                };

                return Ok(health);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Health check error: {ex.Message}");
                return StatusCode(500, new { status = "error", message = ex.Message });
            }
        }

        private async Task<bool> CheckFFmpegAsync()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ffmpeg",
                        Arguments = "-version",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    }
                };

                process.Start();
                await process.WaitForExitAsync();
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }
    }

    // Enhanced Background Service
    public class NvrService : BackgroundService
    {
        private readonly ILogger<NvrService> _logger;
        private readonly ConfigurationManager _configManager;
        private readonly RtspStreamManager _streamManager;
        private readonly DatabaseService? _database;

        public NvrService(ILogger<NvrService> logger, ConfigurationManager configManager, RtspStreamManager streamManager, DatabaseService? database = null)
        {
            _logger = logger;
            _configManager = configManager;
            _streamManager = streamManager;
            _database = database;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("🚀 Enhanced Enterprise NVR Service starting...");

            var config = _configManager.GetConfiguration();
            
            foreach (var camera in config.Cameras.Where(c => c.Enabled))
            {
                try
                {
                    await _streamManager.StartCameraAsync(camera);
                    _database?.LogEvent(camera.Id, "ServiceStart", $"Auto-started camera {camera.Name} during service startup");
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to auto-start camera {camera.Name}: {ex.Message}");
                    _database?.LogEvent(camera.Id, "ServiceStartError", $"Failed to auto-start camera: {ex.Message}", "Error");
                }
            }

            _logger.LogInformation($"✅ Started {config.Cameras.Count(c => c.Enabled)} cameras");

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }

            _logger.LogInformation("🛑 Enhanced Enterprise NVR Service stopping...");
        }
    }

    // Main Program
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Load configuration from file so we can read initial settings
            builder.Configuration.AddJsonFile("/etc/nvr/config.json", optional: true);
            var config = builder.Configuration.Get<NvrConfig>() ?? new NvrConfig();

            // Configure services
            builder.Services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
                });

            // Core NVR services
            builder.Services.AddSingleton<ConfigurationManager>();
            builder.Services.AddSingleton<StorageManager>();

            // Optional enhanced services (only if authentication is enabled)
            if (config.RequireAuthentication)
            {
                // Add enhanced services with authentication
                builder.Services.AddSingleton<DatabaseService>(provider =>
                {
                    var logger = provider.GetRequiredService<ILogger<DatabaseService>>();
                    var configMgr = provider.GetRequiredService<ConfigurationManager>();
                    return new DatabaseService(logger, configMgr.GetConfiguration());
                });

                builder.Services.AddSingleton<AuthenticationService>(provider =>
                {
                    var db = provider.GetRequiredService<DatabaseService>();
                    var logger = provider.GetRequiredService<ILogger<AuthenticationService>>();
                    var configMgr = provider.GetRequiredService<ConfigurationManager>();
                    return new AuthenticationService(db, logger, configMgr.GetConfiguration());
                });

                // JWT Authentication
                builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.JwtSecret)),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ClockSkew = TimeSpan.Zero
                        };
                    });

                builder.Services.AddAuthorization();
            }


            builder.Services.AddSingleton<VideoStreamingService>();
            
            builder.Services.AddSingleton<MetricsCollector>(provider =>
            {
                var logger = provider.GetRequiredService<ILogger<MetricsCollector>>();
                var storageManager = provider.GetRequiredService<StorageManager>();
                var streamManager = provider.GetRequiredService<RtspStreamManager>();
                var db = provider.GetService<DatabaseService>();
                return new MetricsCollector(logger, storageManager, streamManager, db);
            });
            
            builder.Services.AddSingleton<RtspStreamManager>(provider =>
            {
                var logger = provider.GetRequiredService<ILogger<RtspStreamManager>>();
                var configMgr = provider.GetRequiredService<ConfigurationManager>();
                var storageManager = provider.GetRequiredService<StorageManager>();
                var db = provider.GetService<DatabaseService>();
                return new RtspStreamManager(logger, configMgr.GetConfiguration(), storageManager, db);
            });
            
            builder.Services.AddHostedService<NvrService>();

            var app = builder.Build();

            // Configure pipeline
            if (config.RequireAuthentication)
            {
                app.UseAuthentication();
                app.UseAuthorization();
            }
            
            app.UseRouting();
            app.UseStaticFiles();
            app.MapControllers();
            app.MapFallbackToFile("index.html");

            // Startup message
            Console.WriteLine($"🚀 Enhanced Enterprise NVR System Starting...");
            Console.WriteLine($"📡 Web Interface: http://0.0.0.0:{config.WebPort}");
            Console.WriteLine($"🔒 Authentication: {(config.RequireAuthentication ? "Enabled (JWT + Database)" : "Disabled (Backward Compatible)")}");
            Console.WriteLine($"📁 Storage: {config.StorageBasePath}");
            Console.WriteLine($"🎥 Max Streams: {config.MaxConcurrentStreams}");
            if (config.RequireAuthentication)
            {
                Console.WriteLine($"🔐 Default Login: admin/admin123! (CHANGE IMMEDIATELY!)");
                Console.WriteLine($"🗄️  Database: SQLite with audit logging");
                Console.WriteLine($"📹 Features: Live streaming, recordings, thumbnails, authentication");
            }
            else
            {
                Console.WriteLine($"⚠️  Running in compatibility mode (no authentication)");
                Console.WriteLine($"💡 To enable authentication, set RequireAuthentication: true in config");
            }
            Console.WriteLine();

            await app.RunAsync($"http://0.0.0.0:{config.WebPort}");
        }
    }
}