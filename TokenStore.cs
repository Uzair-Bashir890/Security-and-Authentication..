using System.Collections.Concurrent;

public static class TokenStore
{
    private static readonly ConcurrentDictionary<string, string> _map = new();

    public static string IssueToken(string username)
    {
        var token = System.Guid.NewGuid().ToString("N");
        _map[token] = username;
        return token;
    }

    public static string? GetUsername(string token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        return _map.TryGetValue(token, out var username) ? username : null;
    }

    public static void Revoke(string token) => _map.TryRemove(token, out _);
}
