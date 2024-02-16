using JuiceShopDotNet.Common.Cryptography.SymmetricEncryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JuiceShopDotNet.Safe.Tests;

[TestClass]
public class TestSymmetricEncryption
{
    [TestMethod]
    public void TestEncryptDecryptAES128()
    {
        var value = "There can be only one";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.AES128));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.AES128);
        var decrypted = encryptionService.Decrypt(encrypted, "TestKey");

        Assert.AreEqual(value, decrypted);
    }

    [TestMethod]
    public void TestEncryptDecryptAES256()
    {
        var value = "May the force be with you";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.AES256));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.AES256);
        var decrypted = encryptionService.Decrypt(encrypted, "TestKey");

        Assert.AreEqual(value, decrypted);
    }

    [TestMethod]
    public void TestEncryptDecryptTwofish128()
    {
        var value = "Life is like a box of chocolates. You never know what you're going to get.";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.Twofish128));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.Twofish128);
        var decrypted = encryptionService.Decrypt(encrypted, "TestKey");

        Assert.AreEqual(value, decrypted);
    }

    [TestMethod]
    public void TestEncryptDecryptTwofish256()
    {
        //var value = "Houston, we have a problem.";
        var value = "Life is like a box of chocolates. You never know what you're going to get.Life is like a box of chocolates. You never know what you're going to get.";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.Twofish256));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.Twofish256);
        var decrypted = encryptionService.Decrypt(encrypted, "TestKey");

        Assert.AreEqual(value, decrypted);
    }

    [TestMethod]
    public void TestDecryptWithWrongKey()
    {
        var value = "We're not in Kansas anymore";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey1", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.AES128));
        mockKeyStore.CreateKey("TestKey2", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.AES128));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted = encryptionService.Encrypt(value, "TestKey1", 1, EncryptionService.EncryptionAlgorithm.AES128);

        try
        {
            var decrypted = encryptionService.Decrypt(encrypted, "TestKey2");
            Assert.AreNotEqual(value, decrypted);
        }
        catch (CryptographicException ex) //We may get an exception by using the wrong key. Most important thing is that we don't successfully decrypt the value.
        { }
    }

    [TestMethod]
    public void TestEncryptDifferentIVs()
    {
        var value = "There's no crying in baseball!";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.AES128));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted1 = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.AES128);
        var encrypted2 = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.AES128);

        Assert.AreNotEqual(encrypted1, encrypted2);

        var decrypted1 = encryptionService.Decrypt(encrypted1, "TestKey");
        var decrypted2 = encryptionService.Decrypt(encrypted2, "TestKey");

        Assert.AreEqual(value, decrypted1);
        Assert.AreEqual(decrypted2, decrypted1);
    }

    [TestMethod]
    public void TestEncryptDifferentIVs_Twofish()
    {
        var value = "There's no crying in baseball!";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.Twofish128));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted1 = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.Twofish128);
        var encrypted2 = encryptionService.Encrypt(value, "TestKey", 1, EncryptionService.EncryptionAlgorithm.Twofish128);

        Assert.AreNotEqual(encrypted1, encrypted2);

        var decrypted1 = encryptionService.Decrypt(encrypted1, "TestKey");
        var decrypted2 = encryptionService.Decrypt(encrypted2, "TestKey");

        Assert.AreEqual(value, decrypted1);
        Assert.AreEqual(decrypted2, decrypted1);
    }

    [TestMethod]
    public void TestEncryptDifferentAlgorithms()
    {
        var value = "They call me Doctor Worm";

        var mockKeyStore = new MockKeyStore();
        mockKeyStore.CreateKey("TestKey128", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.AES128));
        mockKeyStore.CreateKey("TestKey256", EncryptionService.GetKeyLengthForAlgorithm(EncryptionService.EncryptionAlgorithm.AES256));

        var encryptionService = new EncryptionService(mockKeyStore);
        var encrypted128 = encryptionService.Encrypt(value, "TestKey128", 1, EncryptionService.EncryptionAlgorithm.AES128);
        var encrypted256 = encryptionService.Encrypt(value, "TestKey256", 1, EncryptionService.EncryptionAlgorithm.AES256);

        Assert.AreNotEqual(encrypted128, encrypted256);

        var decrypted1 = encryptionService.Decrypt(encrypted128, "TestKey128");
        var decrypted2 = encryptionService.Decrypt(encrypted256, "TestKey256");

        Assert.AreEqual(value, decrypted1);
        Assert.AreEqual(decrypted2, decrypted1);
    }
}
