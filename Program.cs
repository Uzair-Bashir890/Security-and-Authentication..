using System.Data;
using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Threading.Tasks;

var builder = WebApplication.CreateBuilder(args);

// Register services
// Use a simple SQLite-backed Database wrapper and a basic AuthService.
// In a real app replace these with your implementations and secure secrets.
builder.Services.AddSingleton<Database>(_ => new Database("Data Source=SafeVault.db"));
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<SafeVault.Services.UserRepository>(_ =>
{
    // Use the SQLite provider factory
    var factory = SqliteFactory.Instance;
    var connectionString = "Data Source=SafeVault.db";
    return new SafeVault.Services.UserRepository(factory, connectionString);
});

var app = builder.Build();

// Ensure DB and tables exist (simple initialization for demo)
Database.InitializeIfNeeded("Data Source=SafeVault.db");

app.MapGet("/", () => Results.Ok(new { service = "SafeVault.Web", status = "running" }));

app.MapPost("/register", async (RegisterRequest req, AuthService auth) =>
{
    try
    {
        await auth.RegisterUserAsync(req.Username, req.Email, req.Password, req.Role ?? "user");
        return Results.Ok(new { success = true });
    }
    catch (System.Exception e)
    {
        return Results.BadRequest(new { error = e.Message });
    }
});

app.MapPost("/login", (LoginRequest req, AuthService auth) =>
{
    var user = auth.AuthenticateUser(req.Username, req.Password);
    if (user == null) return Results.Unauthorized();
    var token = TokenStore.IssueToken(user.Username);
    return Results.Ok(new { token, username = user.Username, role = user.Role });
});

app.MapGet("/admin", (HttpRequest request, AuthService auth, Database db) =>
{
    if (!request.Headers.TryGetValue("X-Auth-Token", out var token)) return Results.Unauthorized();
    var username = TokenStore.GetUsername(token.ToString());
    if (username == null) return Results.Unauthorized();
    var user = db.GetUserWithCredentials(username);
    if (user == null) return Results.Unauthorized();
    if (!auth.Authorize(user, "admin")) return Results.Forbid();
    return Results.Ok(new { secret = "VerySensitiveAdminData" });
});

app.Run();


// DTOs
public record RegisterRequest(string Username, string Email, string Password, string? Role);
public record LoginRequest(string Username, string Password);


// Simple Database wrapper for SQLite (synchronous methods kept simple for demo)
public class Database
{
    private readonly string _connectionString;
    public Database(string connectionString) => _connectionString = connectionString;

    public static void InitializeIfNeeded(string connectionString)
    {
        using var conn = new SqliteConnection(connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL,
                PasswordHash TEXT NOT NULL,
                Role TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS Notes (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                UserId INTEGER NOT NULL,
                Title TEXT NOT NULL,
                Content TEXT NOT NULL,
                FOREIGN KEY(UserId) REFERENCES Users(Id)
            );
        ";
        cmd.ExecuteNonQuery();
    }

    public UserRecord? GetUserWithCredentials(string username)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, Username, Email, PasswordHash, Role FROM Users WHERE Username = @u";
        cmd.Parameters.AddWithValue("@u", username);

        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            return new UserRecord
            {
                Id = reader.GetInt32(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2),
                PasswordHash = reader.GetString(3),
                Role = reader.GetString(4)
            };
        }

        return null;
    }

    public int InsertUser(string username, string email, string passwordHash, string role)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@u, @e, @p, @r)";
        cmd.Parameters.AddWithValue("@u", username);
        cmd.Parameters.AddWithValue("@e", email);
        cmd.Parameters.AddWithValue("@p", passwordHash);
        cmd.Parameters.AddWithValue("@r", role);

        return cmd.ExecuteNonQuery();
    }

    public record UserRecord
    {
        public int Id { get; init; }
        public string Username { get; init; } = string.Empty;
        public string Email { get; init; } = string.Empty;
        public string PasswordHash { get; init; } = string.Empty;
        public string Role { get; init; } = "user";
    }
}


// Minimal AuthService for demo purposes (use a secure password hasher in production)
public class AuthService
{
    private readonly Database _db;
    public AuthService(Database db) => _db = db;

    public async Task RegisterUserAsync(string username, string email, string password, string role)
    {
        // basic validation
        if (string.IsNullOrWhiteSpace(username)) throw new System.ArgumentException("username required");
        if (string.IsNullOrWhiteSpace(password)) throw new System.ArgumentException("password required");

        // DO NOT use plain text in production. Use a proper password hasher (e.g., ASP.NET Core Identity PBKDF2)
        var hash = SimpleHash(password);

        // Insert using Database wrapper which uses parameterized queries
        var inserted = _db.InsertUser(username, email, hash, role);
        if (inserted <= 0) throw new System.Exception("Could not create user");
        await Task.CompletedTask;
    }

    public AuthUser? AuthenticateUser(string username, string password)
    {
        var record = _db.GetUserWithCredentials(username);
        if (record == null) return null;
        var hash = SimpleHash(password);
        if (hash != record.PasswordHash) return null;
        return new AuthUser { Username = record.Username, Role = record.Role };
    }

    public bool Authorize(Database.UserRecord user, string requiredRole)
    {
        if (user == null) return false;
        return string.Equals(user.Role, requiredRole, System.StringComparison.OrdinalIgnoreCase);
    }

    private static string SimpleHash(string input)
    {
        // placeholder hash; replace with secure password hashing in production
        using var sha = System.Security.Cryptography.SHA256.Create();
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        var hashed = sha.ComputeHash(bytes);
        return System.Convert.ToBase64String(hashed);
    }

    public record AuthUser
    {
        public string Username { get; init; } = string.Empty;
        public string Role { get; init; } = "user";
    }
}


// Simple in-memory token store for demo (not for production)
public static class TokenStore
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _tokens =
        new System.Collections.Concurrent.ConcurrentDictionary<string, string>();

    public static string IssueToken(string username)
    {
        var token = System.Guid.NewGuid().ToString("N");
        _tokens[token] = username;
        return token;
    }

    public static string? GetUsername(string token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        return _tokens.TryGetValue(token, out var username) ? username : null;
    }
}


// Parameterized repository (from your earlier code) — kept async and using DbProviderFactory
namespace SafeVault.Services
{
    using System.Threading.Tasks;

    public class UserRepository
    {
        private readonly DbProviderFactory _factory;
        private readonly string _connectionString;

        public UserRepository(DbProviderFactory factory, string connectionString)
        {
            _factory = factory;
            _connectionString = connectionString;
        }

        public async Task<User?> GetUserByIdAsync(int userId)
        {
            using var conn = _factory.CreateConnection();
            conn!.ConnectionString = _connectionString;
            await conn.OpenAsync();

            using var cmd = conn.CreateCommand();
            cmd.CommandType = CommandType.Text;
            cmd.CommandText = "SELECT Id, Username, Email FROM Users WHERE Id = @Id";
            var p = cmd.CreateParameter();
            p.ParameterName = "@Id";
            p.DbType = DbType.Int32;
            p.Value = userId;
            cmd.Parameters.Add(p);

            using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new User
                {
                    Id = reader.GetInt32(0),
                    Username = reader.GetString(1),
                    Email = reader.GetString(2)
                };
            }

            return null;
        }

        public async Task<bool> InsertNoteAsync(int userId, string title, string content)
        {
            using var conn = _factory.CreateConnection();
            conn!.ConnectionString = _connectionString;
            await conn.OpenAsync();

            using var cmd = conn.CreateCommand();
            cmd.CommandType = CommandType.Text;
            cmd.CommandText =
                "INSERT INTO Notes (UserId, Title, Content) VALUES (@UserId, @Title, @Content)";

            var pUser = cmd.CreateParameter();
            pUser.ParameterName = "@UserId";
            pUser.DbType = DbType.Int32;
            pUser.Value = userId;
            cmd.Parameters.Add(pUser);

            var pTitle = cmd.CreateParameter();
            pTitle.ParameterName = "@Title";
            pTitle.DbType = DbType.String;
            pTitle.Value = title;
            cmd.Parameters.Add(pTitle);

            var pContent = cmd.CreateParameter();
            pContent.ParameterName = "@Content";
            pContent.DbType = DbType.String;
            pContent.Value = content;
            cmd.Parameters.Add(pContent);

            var rows = await cmd.ExecuteNonQueryAsync();
            return rows > 0;
        }
    }

    public record User
    {
        public int Id { get; init; }
        public string Username { get; init; } = string.Empty;
        public string Email { get; init; } = string.Empty;
    }
};
