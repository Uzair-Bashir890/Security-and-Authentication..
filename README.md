# SafeVaultActivity (mini sample)
This small project demonstrates input sanitization, parameterized queries, and tests to detect SQL injection and XSS risks.

How to run tests (PowerShell on Windows)
- Ensure .NET SDK 6+ is installed.
- From the workspace root (where `SafeVaultActivity` folder is), run:

```powershell
dotnet restore
dotnet test
```

Notes and assumptions
- Tests use in-memory SQLite and verify that parameterized queries prevent injected SQL from executing.
- `InputSanitizer.HtmlEncode` should be used before rendering user content in HTML contexts.
- `SanitizeEmail` does a simple validation; for production use, consider a robust library and additional checks (MX, length, normalization).

Security contract (short)
- Inputs: username (string), email (string).
- Outputs: sanitized username/email; HTML-encoded strings for safe rendering.
- Error modes: invalid email returns empty string; usernames trimmed and disallowed chars removed.
- Success criteria: sanitized values don't contain angle brackets or disallowed chars; DB access uses parameterized queries.

Edge cases considered
- Empty/null inputs
- Very long inputs (truncated to safe max)
- Inputs containing SQL meta-characters or HTML tags

Next steps
- Integrate with real web endpoint (use ASP.NET Core minimal API) and apply server-side validation before DB operations.
- Add authentication and authorization (Activity 2).
- Add logging and secure configuration for DB connection strings (do not hardcode secrets).
