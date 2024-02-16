using JuiceShopDotNet.Common.Cryptography.Hashing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JuiceShopDotNet.Safe.Tests;

[TestClass]
public class TestHashing
{
    [TestMethod]
    public void TestSaltedHashEqual()
    { 
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", 32);

        var toHash = "Don't have a cow, man";

        var hasher1 = new HashingService(mockKeyStore);
        var hashed1 = hasher1.CreateSaltedHash(toHash, "TestKey", 1, HashingService.HashAlgorithm.SHA1);

        var hasher2 = new HashingService(mockKeyStore);
        var hashed2 = hasher2.CreateSaltedHash(toHash, "TestKey", 1, HashingService.HashAlgorithm.SHA1);

        Assert.AreEqual(hashed1, hashed2);
    }

    [TestMethod]
    public void TestSaltedHashNotEqual_DifferentAlgorithm()
    {
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", 32);

        var toHash = "All your base belong to us";

        var hasher = new HashingService(mockKeyStore);
        var hashedSHA256 = hasher.CreateSaltedHash(toHash, "TestKey", 1, HashingService.HashAlgorithm.SHA2_256);
        var hashedSHA512 = hasher.CreateSaltedHash(toHash, "TestKey", 1, HashingService.HashAlgorithm.SHA2_512);

        Assert.AreNotEqual(hashedSHA256, hashedSHA512);
    }

    [TestMethod]
    public void TestSaltedHashNotEqual_DifferentText()
    {
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", 32);

        var hasher = new HashingService(mockKeyStore);
        var starTrekHashed = hasher.CreateSaltedHash("Make it so", "TestKey", 1, HashingService.HashAlgorithm.SHA3_512);
        var starWarsHashed = hasher.CreateSaltedHash("May the force be with you", "TestKey", 1, HashingService.HashAlgorithm.SHA3_512);

        Assert.AreNotEqual(starTrekHashed, starWarsHashed);
    }

    [TestMethod]
    public void TestUnsaltedHashEqual()
    {
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", 32);

        var toHash = "Don't have a cow, man";

        var hasher1 = new HashingService(mockKeyStore);
        var hashed1 = hasher1.CreateUnsaltedHash(toHash, HashingService.HashAlgorithm.SHA1);

        var hasher2 = new HashingService(mockKeyStore);
        var hashed2 = hasher2.CreateUnsaltedHash(toHash, HashingService.HashAlgorithm.SHA1);

        Assert.AreEqual(hashed1, hashed2);
    }

    [TestMethod]
    public void TestUnsaltedHashNotEqual_DifferentAlgorithm()
    {
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", 32);

        var toHash = "All your base belong to us";

        var hasher = new HashingService(mockKeyStore);
        var hashedSHA256 = hasher.CreateUnsaltedHash(toHash, HashingService.HashAlgorithm.SHA2_256);
        var hashedSHA512 = hasher.CreateUnsaltedHash(toHash, HashingService.HashAlgorithm.SHA2_512);

        Assert.AreNotEqual(hashedSHA256, hashedSHA512);
    }

    [TestMethod]
    public void TestUnsaltedHashNotEqual_DifferentText()
    {
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", 32);

        var hasher = new HashingService(mockKeyStore);
        var starTrekHashed = hasher.CreateUnsaltedHash("Make it so", HashingService.HashAlgorithm.SHA3_512);
        var starWarsHashed = hasher.CreateUnsaltedHash("May the force be with you", HashingService.HashAlgorithm.SHA3_512);

        Assert.AreNotEqual(starTrekHashed, starWarsHashed);
    }

    [TestMethod]
    public void TestMatchesHash()
    {
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", 32);

        var toHash = "One ring to rule them all";

        var hasher = new HashingService(mockKeyStore);
        var hashed = hasher.CreateSaltedHash(toHash, "TestKey", 1, HashingService.HashAlgorithm.SHA2_256);

        Assert.IsTrue(hasher.MatchesHash(toHash, hashed, "TestKey"));
    }

    [TestMethod]
    public void TestMatchesHash_DifferentKey()
    {
        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey1", 32);
        mockKeyStore.CreateKey("TestKey2", 32);

        var toHash = "One ring to rule them all";

        var hasher = new HashingService(mockKeyStore);
        var hashed = hasher.CreateSaltedHash(toHash, "TestKey1", 1, HashingService.HashAlgorithm.SHA2_256);

        Assert.IsFalse(hasher.MatchesHash(toHash, hashed, "TestKey2"));
    }
}
