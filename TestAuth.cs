using NUnit.Framework;
using SafeVault;

[TestFixture]
public class TestAuth
{
    [Test]
    public void TestRegisterAndAuthenticate_Success()
    {
        using var db = new Database("Data Source=:memory:");
        var auth = new AuthService(db);

        auth.RegisterUser("alice", "alice@example.com", "P@ssw0rd!", "user");

        var user = auth.AuthenticateUser("alice", "P@ssw0rd!");
        Assert.IsNotNull(user, "Authentication should succeed with correct password.");
        Assert.AreEqual("alice", user!.Username);
        Assert.AreEqual("user", user.Role);
    }

    [Test]
    public void TestAuthenticate_FailsOnWrongPassword()
    {
        using var db = new Database("Data Source=:memory:");
        var auth = new AuthService(db);

        auth.RegisterUser("bob", "bob@example.com", "CorrectHorseBatteryStaple", "user");

        var user = auth.AuthenticateUser("bob", "wrong-password");
        Assert.IsNull(user, "Authentication must fail for wrong password.");
    }

    [Test]
    public void TestRoleBasedAuthorization_AdminOnly()
    {
        using var db = new Database("Data Source=:memory:");
        var auth = new AuthService(db);

        auth.RegisterUser("adminuser", "admin@example.com", "Adm1nPass!", "admin");
        auth.RegisterUser("regular", "reg@example.com", "UserPass123", "user");

        var admin = auth.AuthenticateUser("adminuser", "Adm1nPass!");
        var regular = auth.AuthenticateUser("regular", "UserPass123");

        Assert.IsNotNull(admin);
        Assert.IsNotNull(regular);

        Assert.IsTrue(auth.Authorize(admin, "admin"), "Admin should be authorized for admin role.");
        Assert.IsFalse(auth.Authorize(regular, "admin"), "Regular user should not be authorized for admin role.");
    }
}
