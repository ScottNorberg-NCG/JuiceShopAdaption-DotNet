using JuiceShopDotNet.Common.Cryptography.AsymmetricEncryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JuiceShopDotNet.Tests;

[TestClass]
public class TestDigitalSignature
{
    [TestMethod]
    public void TestSignature_PrivateKey()
    {
        var secretStore = new MockKeyStore();

        var signatureService = new SignatureService(secretStore);
        var keyPair = signatureService.GenerateKeys();

        secretStore.CreateKey("PUBLIC_KEY", keyPair.PublicKey);
        secretStore.CreateKey("PRIVATE_KEY", keyPair.PrivateKey);

        var text = "Life is pain, Princess. Anyone who tells you different is selling something.";
        var signed = signatureService.CreateSignature(text, "PRIVATE_KEY", 1, SignatureService.SignatureAlgorithm.RSA2048SHA512);
        Assert.IsTrue(signatureService.VerifySignature(text, signed, "PUBLIC_KEY"));
    }

    [TestMethod]
    public void TestSignature_DifferentKey()
    {
        var secretStore = new MockKeyStore();

        var signatureService = new SignatureService(secretStore);

        var keyPair1 = signatureService.GenerateKeys();
        secretStore.CreateKey("PUBLIC_KEY_1", keyPair1.PublicKey);
        secretStore.CreateKey("PRIVATE_KEY_1", keyPair1.PrivateKey);

        var keyPair2 = signatureService.GenerateKeys();
        secretStore.CreateKey("PUBLIC_KEY_2", keyPair2.PublicKey);
        secretStore.CreateKey("PRIVATE_KEY_2", keyPair2.PrivateKey);

        var text = "My name is Inigo Montoya. You killed my father. Prepare to die";
        var signed = signatureService.CreateSignature(text, "PRIVATE_KEY_1", 1, SignatureService.SignatureAlgorithm.RSA2048SHA512);
        Assert.IsFalse(signatureService.VerifySignature(text, signed, "PUBLIC_KEY_2"));
    }
}
