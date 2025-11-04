using NUnit.Framework;
using SafeVault;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void TestForSQLInjection()
    {
        // Use in-memory SQLite for tests (fast, isolated)
        using var db = new Database("Data Source=:memory:");
        // Typical SQLi attempt
        var malicious = "attacker'; DROP TABLE Users; --";
        // Sanitize username to remove disallowed characters (optional — DB uses parameterized queries anyway)
        var safeName = InputSanitizer.SanitizeUsername(malicious);
        // Insert with parameterized query; parameterization prevents the injected SQL from executing
        db.InsertUser(safeName, "attacker@example.com");

        // Table must still exist and contain one record
        Assert.AreEqual(1, db.CountUsers(), "Table should still have one user; SQL injection should not have executed.");
        var fetched = db.GetUserByUsername(safeName);
        Assert.IsNotNull(fetched);
        Assert.AreEqual(safeName, fetched);
    }

    [Test]
    public void TestForXSS()
    {
        var xss = "<script>alert('xss')</script>";
        var encoded = InputSanitizer.HtmlEncode(xss);
        // HTML encode should remove literal angle brackets
        Assert.IsFalse(encoded.Contains("<") || encoded.Contains(">"), "HTML should be encoded and not contain angle brackets.");
    // Encoded output should contain encoded script tag markers (angle brackets encoded)
    Assert.IsTrue(encoded.ToLower().Contains("&lt;script"), "Encoded output should contain encoded script tag sequence (angle brackets encoded).");
    }
}
