namespace SafeVault;
using Microsoft.Data.Sqlite;
using System;

public class Database : IDisposable
{
    private readonly SqliteConnection _conn;

    public Database(string connectionString)
    {
        _conn = new SqliteConnection(connectionString);
        _conn.Open();
        Initialize();
    }

    private void Initialize()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT,
                Email TEXT,
                PasswordHash TEXT,
                Role TEXT
            );
        ";
        cmd.ExecuteNonQuery();
    }

    // Uses parameterized query to avoid SQL injection.
    public void InsertUser(string username, string email)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Users (Username, Email) VALUES (@username, @email);";
        cmd.Parameters.AddWithValue("@username", username ?? string.Empty);
        cmd.Parameters.AddWithValue("@email", email ?? string.Empty);
        cmd.ExecuteNonQuery();
    }

    // Insert with credentials and role (used by AuthService)
    public void InsertUserWithCredentials(string username, string email, string passwordHash, string role)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@username, @email, @passwordHash, @role);";
        cmd.Parameters.AddWithValue("@username", username ?? string.Empty);
        cmd.Parameters.AddWithValue("@email", email ?? string.Empty);
        cmd.Parameters.AddWithValue("@passwordHash", passwordHash ?? string.Empty);
        cmd.Parameters.AddWithValue("@role", role ?? string.Empty);
        cmd.ExecuteNonQuery();
    }

    public string? GetUserByUsername(string username)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT Username FROM Users WHERE Username = @username LIMIT 1;";
        cmd.Parameters.AddWithValue("@username", username ?? string.Empty);
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
            return reader.GetString(0);
        return null;
    }

    // Fetch user record including password hash and role
    public User? GetUserWithCredentials(string username)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT Username, Email, PasswordHash, Role FROM Users WHERE Username = @username LIMIT 1;";
        cmd.Parameters.AddWithValue("@username", username ?? string.Empty);
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            var user = new User
            {
                Username = reader.IsDBNull(0) ? string.Empty : reader.GetString(0),
                Email = reader.IsDBNull(1) ? string.Empty : reader.GetString(1),
                PasswordHash = reader.IsDBNull(2) ? string.Empty : reader.GetString(2),
                Role = reader.IsDBNull(3) ? string.Empty : reader.GetString(3)
            };
            return user;
        }
        return null;
    }

    public int CountUsers()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Users;";
        var scalar = cmd.ExecuteScalar();
        return Convert.ToInt32(scalar);
    }

    public void Dispose()
    {
        _conn?.Dispose();
    }
}
