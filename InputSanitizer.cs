namespace SafeVault;
using System.Text.RegularExpressions;
using System;

public static class InputSanitizer
{
    // Allow letters, digits, underscore, dash and dot. Remove anything else.
    private static readonly Regex DisallowedUsernameChars = new(@"[^\w\-\.\@]", RegexOptions.Compiled);

    public static string SanitizeUsername(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        var trimmed = input.Trim();
        // enforce max length
        if (trimmed.Length > 50) trimmed = trimmed.Substring(0, 50);
        // remove disallowed characters
        var cleaned = DisallowedUsernameChars.Replace(trimmed, string.Empty);
        return cleaned;
    }

    // Basic email validation; return empty string for invalid emails.
    public static string SanitizeEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email)) return string.Empty;
        var trimmed = email.Trim();
        if (trimmed.Length > 254) trimmed = trimmed.Substring(0, 254);
        var ok = Regex.IsMatch(trimmed, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        return ok ? trimmed : string.Empty;
    }

    // HTML-encode to prevent XSS when rendering user input back to web pages.
    public static string HtmlEncode(string? input)
    {
        if (input == null) return string.Empty;
        return System.Net.WebUtility.HtmlEncode(input);
    }
}
