namespace SafeVault;
using System;
using BCrypt = BCrypt.Net.BCrypt;

public class AuthService
{
    private readonly Database _db;

    public AuthService(Database db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
    }

    // Registers a user: sanitize inputs, hash password, and store role
    public void RegisterUser(string username, string email, string password, string role = "user")
    {
        var cleanUser = InputSanitizer.SanitizeUsername(username);
        var cleanEmail = InputSanitizer.SanitizeEmail(email);
        if (string.IsNullOrEmpty(cleanUser)) throw new ArgumentException("Invalid username", nameof(username));
        if (string.IsNullOrEmpty(cleanEmail)) throw new ArgumentException("Invalid email", nameof(email));
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("Password required", nameof(password));

        // Use BCrypt to hash the password with a safe default work factor
    var hash = BCrypt.HashPassword(password);

        _db.InsertUserWithCredentials(cleanUser, cleanEmail, hash, role);
    }

    // Authenticate and return user when successful, otherwise null
    public User? AuthenticateUser(string username, string password)
    {
        var cleanUser = InputSanitizer.SanitizeUsername(username);
        if (string.IsNullOrEmpty(cleanUser)) return null;
        var user = _db.GetUserWithCredentials(cleanUser);
        if (user == null) return null;
    var ok = BCrypt.Verify(password ?? string.Empty, user.PasswordHash ?? string.Empty);
        return ok ? user : null;
    }

    // Simple RBAC check
    public bool Authorize(User? user, string requiredRole)
    {
        if (user == null) return false;
        if (string.IsNullOrEmpty(requiredRole)) return true; // no role required
        return string.Equals(user.Role ?? string.Empty, requiredRole, StringComparison.OrdinalIgnoreCase);
    }
}
