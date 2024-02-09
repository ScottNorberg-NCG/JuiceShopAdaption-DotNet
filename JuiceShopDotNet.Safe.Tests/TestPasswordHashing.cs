using JuiceShopDotNet.Safe.Cryptography.Hashing;

namespace JuiceShopDotNet.Safe.Tests;

[TestClass]
public class TestPasswordHashing
{
    [TestMethod]
    public void TestPasswordVerification()
    {
        var password = "This is a passphrase!";

        var passwordHasher = new PasswordHashingService();

        var hashed = passwordHasher.HashPassword(null, password);
        Assert.IsTrue(passwordHasher.VerifyHashedPassword(null, hashed, "This is a passphrase!") == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success);
    }

    [TestMethod]
    public void TestPasswordHashUnique()
    {
        var password = "S0meR@ndomPas$worD!";

        var passwordHasher = new PasswordHashingService();

        var hashed1 = passwordHasher.HashPassword(null, password);
        var hashed2 = passwordHasher.HashPassword(null, password);
        Assert.AreNotEqual(hashed1, hashed2);
    }
}