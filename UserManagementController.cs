using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Data.SQLite;

namespace EnterpriseNVR  // Match your existing namespace
{
    // Additional User Management Models
    public class CreateUserRequest
    {
        [Required]
        [StringLength(50, MinimumLength = 3)]
        public string Username { get; set; } = string.Empty;
        
        [Required]
        [StringLength(100, MinimumLength = 8)]
        public string Password { get; set; } = string.Empty;
        
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
        
        public string[] Roles { get; set; } = Array.Empty<string>();
        public string[] AllowedCameras { get; set; } = Array.Empty<string>();
        public bool IsActive { get; set; } = true;
    }

    public class UpdateUserRequest
    {
        public string? Username { get; set; }
        public string? Email { get; set; }
        public string[]? Roles { get; set; }
        public string[]? AllowedCameras { get; set; }
        public bool? IsActive { get; set; }
    }

    public class ChangePasswordRequest
    {
        [Required]
        public string CurrentPassword { get; set; } = string.Empty;
        
        [Required]
        [StringLength(100, MinimumLength = 8)]
        public string NewPassword { get; set; } = string.Empty;
    }

    public class UserResponse
    {
        public string Id { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string[] Roles { get; set; } = Array.Empty<string>();
        public string[] AllowedCameras { get; set; } = Array.Empty<string>();
        public DateTime CreatedAt { get; set; }
        public DateTime LastLogin { get; set; }
        public bool IsActive { get; set; }
    }

    // Extend the existing DatabaseService with user management methods
    public partial class DatabaseService
    {
        public List<User> GetAllUsers()
        {
            var users = new List<User>();
            
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                connection.Open();

                const string query = "SELECT * FROM Users ORDER BY Username";
                using var command = new SQLiteCommand(query, connection);
                using var reader = command.ExecuteReader();

                while (reader.Read())
                {
                    users.Add(new User
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
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to get users: {ex.Message}");
            }

            return users;
        }

        public User? GetUserById(string userId)
        {
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                connection.Open();

                const string query = "SELECT * FROM Users WHERE Id = @Id";
                using var command = new SQLiteCommand(query, connection);
                command.Parameters.AddWithValue("@Id", userId);

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
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to get user by id: {ex.Message}");
            }

            return null;
        }

        public bool UpdateUser(string userId, UpdateUserRequest request)
        {
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                connection.Open();

                var setParts = new List<string>();
                var parameters = new List<(string name, object value)>();

                if (!string.IsNullOrEmpty(request.Username))
                {
                    setParts.Add("Username = @Username");
                    parameters.Add(("@Username", request.Username));
                }

                if (!string.IsNullOrEmpty(request.Email))
                {
                    setParts.Add("Email = @Email");
                    parameters.Add(("@Email", request.Email));
                }

                if (request.Roles != null)
                {
                    setParts.Add("Roles = @Roles");
                    parameters.Add(("@Roles", JsonSerializer.Serialize(request.Roles)));
                }

                if (request.AllowedCameras != null)
                {
                    setParts.Add("AllowedCameras = @AllowedCameras");
                    parameters.Add(("@AllowedCameras", JsonSerializer.Serialize(request.AllowedCameras)));
                }

                if (request.IsActive.HasValue)
                {
                    setParts.Add("IsActive = @IsActive");
                    parameters.Add(("@IsActive", request.IsActive.Value ? 1 : 0));
                }

                if (setParts.Count == 0) return false;

                var query = $"UPDATE Users SET {string.Join(", ", setParts)} WHERE Id = @Id";
                
                using var command = new SQLiteCommand(query, connection);
                command.Parameters.AddWithValue("@Id", userId);
                
                foreach (var (name, value) in parameters)
                {
                    command.Parameters.AddWithValue(name, value);
                }

                return command.ExecuteNonQuery() > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to update user: {ex.Message}");
                return false;
            }
        }

        public bool DeleteUser(string userId)
        {
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                connection.Open();

                const string query = "DELETE FROM Users WHERE Id = @Id";
                using var command = new SQLiteCommand(query, connection);
                command.Parameters.AddWithValue("@Id", userId);

                return command.ExecuteNonQuery() > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to delete user: {ex.Message}");
                return false;
            }
        }

        public bool ResetPassword(string userId, string newPassword)
        {
            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                connection.Open();

                const string query = "UPDATE Users SET PasswordHash = @PasswordHash WHERE Id = @Id";
                using var command = new SQLiteCommand(query, connection);
                command.Parameters.AddWithValue("@PasswordHash", BCrypt.Net.BCrypt.HashPassword(newPassword));
                command.Parameters.AddWithValue("@Id", userId);

                return command.ExecuteNonQuery() > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to reset password: {ex.Message}");
                return false;
            }
        }

        public Dictionary<string, object> GetUserStatistics()
        {
            var stats = new Dictionary<string, object>();

            try
            {
                using var connection = new SQLiteConnection(_connectionString);
                connection.Open();

                // Total users
                using var totalCommand = new SQLiteCommand("SELECT COUNT(*) FROM Users", connection);
                stats["totalUsers"] = Convert.ToInt32(totalCommand.ExecuteScalar());

                // Active users
                using var activeCommand = new SQLiteCommand("SELECT COUNT(*) FROM Users WHERE IsActive = 1", connection);
                stats["activeUsers"] = Convert.ToInt32(activeCommand.ExecuteScalar());

                // Users by role
                var roleStats = new Dictionary<string, int>();
                using var roleCommand = new SQLiteCommand("SELECT Roles FROM Users WHERE IsActive = 1", connection);
                using var roleReader = roleCommand.ExecuteReader();
                
                while (roleReader.Read())
                {
                    var roles = JsonSerializer.Deserialize<string[]>(roleReader.GetString("Roles")) ?? Array.Empty<string>();
                    foreach (var role in roles)
                    {
                        roleStats[role] = roleStats.GetValueOrDefault(role, 0) + 1;
                    }
                }
                stats["usersByRole"] = roleStats;

                // Recent logins (last 24 hours)
                using var recentCommand = new SQLiteCommand(
                    "SELECT COUNT(*) FROM AuditLog WHERE Action = 'Login' AND Success = 1 AND Timestamp > datetime('now', '-1 day')", 
                    connection);
                stats["recentLogins"] = Convert.ToInt32(recentCommand.ExecuteScalar());

                // Failed login attempts (last 24 hours)
                using var failedCommand = new SQLiteCommand(
                    "SELECT COUNT(*) FROM AuditLog WHERE Action = 'Login' AND Success = 0 AND Timestamp > datetime('now', '-1 day')", 
                    connection);
                stats["failedLogins"] = Convert.ToInt32(failedCommand.ExecuteScalar());

            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to get user statistics: {ex.Message}");
            }

            return stats;
        }
    }

    // User Management Controller
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly DatabaseService _database;
        private readonly ILogger<UsersController> _logger;

        public UsersController(DatabaseService database, ILogger<UsersController> logger)
        {
            _database = database;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult GetUsers()
        {
            try
            {
                var users = _database.GetAllUsers();
                var userResponses = users.Select(u => new UserResponse
                {
                    Id = u.Id,
                    Username = u.Username,
                    Email = u.Email,
                    Roles = u.Roles,
                    AllowedCameras = u.AllowedCameras,
                    CreatedAt = u.CreatedAt,
                    LastLogin = u.LastLogin,
                    IsActive = u.IsActive
                }).ToList();

                return Ok(userResponses);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting users: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpGet("{id}")]
        public IActionResult GetUser(string id)
        {
            try
            {
                var user = _database.GetUserById(id);
                if (user == null)
                {
                    return NotFound(new { error = "User not found" });
                }

                var userResponse = new UserResponse
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email,
                    Roles = user.Roles,
                    AllowedCameras = user.AllowedCameras,
                    CreatedAt = user.CreatedAt,
                    LastLogin = user.LastLogin,
                    IsActive = user.IsActive
                };

                return Ok(userResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting user {id}: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpPost]
        public IActionResult CreateUser([FromBody] CreateUserRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var existingUser = _database.GetUserByUsername(request.Username);
                if (existingUser != null)
                {
                    return Conflict(new { error = "Username already exists" });
                }

                var user = new User
                {
                    Id = Guid.NewGuid().ToString(),
                    Username = request.Username,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
                    Email = request.Email,
                    Roles = request.Roles,
                    AllowedCameras = request.AllowedCameras,
                    IsActive = request.IsActive,
                    CreatedAt = DateTime.UtcNow,
                    LastLogin = DateTime.MinValue
                };

                _database.CreateUser(user);

                var userResponse = new UserResponse
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email,
                    Roles = user.Roles,
                    AllowedCameras = user.AllowedCameras,
                    CreatedAt = user.CreatedAt,
                    LastLogin = user.LastLogin,
                    IsActive = user.IsActive
                };

                return CreatedAtAction(nameof(GetUser), new { id = user.Id }, userResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error creating user: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpPut("{id}")]
        public IActionResult UpdateUser(string id, [FromBody] UpdateUserRequest request)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var user = _database.GetUserById(id);
                if (user == null)
                {
                    return NotFound(new { error = "User not found" });
                }

                if (!string.IsNullOrEmpty(request.Username) && request.Username != user.Username)
                {
                    var existingUser = _database.GetUserByUsername(request.Username);
                    if (existingUser != null)
                    {
                        return Conflict(new { error = "Username already exists" });
                    }
                }

                var success = _database.UpdateUser(id, request);
                if (!success)
                {
                    return StatusCode(500, new { error = "Failed to update user" });
                }

                var updatedUser = _database.GetUserById(id);
                var userResponse = new UserResponse
                {
                    Id = updatedUser!.Id,
                    Username = updatedUser.Username,
                    Email = updatedUser.Email,
                    Roles = updatedUser.Roles,
                    AllowedCameras = updatedUser.AllowedCameras,
                    CreatedAt = updatedUser.CreatedAt,
                    LastLogin = updatedUser.LastLogin,
                    IsActive = updatedUser.IsActive
                };

                return Ok(userResponse);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error updating user {id}: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpDelete("{id}")]
        public IActionResult DeleteUser(string id)
        {
            try
            {
                var user = _database.GetUserById(id);
                if (user == null)
                {
                    return NotFound(new { error = "User not found" });
                }

                var success = _database.DeleteUser(id);
                if (!success)
                {
                    return StatusCode(500, new { error = "Failed to delete user" });
                }

                return NoContent();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error deleting user {id}: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpPost("{id}/reset-password")]
        public IActionResult ResetPassword(string id, [FromBody] Dictionary<string, string> request)
        {
            try
            {
                if (!request.ContainsKey("newPassword"))
                {
                    return BadRequest(new { error = "New password is required" });
                }

                var user = _database.GetUserById(id);
                if (user == null)
                {
                    return NotFound(new { error = "User not found" });
                }

                var success = _database.ResetPassword(id, request["newPassword"]);
                if (!success)
                {
                    return StatusCode(500, new { error = "Failed to reset password" });
                }

                return Ok(new { message = "Password reset successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error resetting password for user {id}: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpGet("roles")]
        public IActionResult GetAvailableRoles()
        {
            var roles = new[]
            {
                new { name = "Administrator", description = "Full system access" },
                new { name = "UserManager", description = "Can manage users and view audit logs" },
                new { name = "Operator", description = "Can view cameras and recordings" },
                new { name = "Viewer", description = "Can only view assigned cameras" }
            };

            return Ok(roles);
        }

        [HttpGet("statistics")]
        public IActionResult GetUserStatistics()
        {
            try
            {
                var stats = _database.GetUserStatistics();
                return Ok(stats);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting user statistics: {ex.Message}");
                return StatusCode(500, new { error = "Internal server error" });
            }
        }

        [HttpGet("activity")]
        public IActionResult GetUserActivity([FromQuery] int limit = 50)
        {
            // Return empty activity for now - your existing system has audit logging
            return Ok(new List<object>());
        }
    }
}