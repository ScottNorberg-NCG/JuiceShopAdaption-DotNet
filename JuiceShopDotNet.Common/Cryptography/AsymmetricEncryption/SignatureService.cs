using JuiceShopDotNet.Common.Cryptography.KeyStorage;
using System.Security.Cryptography;
using System.Text;

namespace JuiceShopDotNet.Common.Cryptography.AsymmetricEncryption;

public class SignatureService(ISecretStore secretStore) : BaseCryptographyProvider, ISignatureService
{
    private readonly ISecretStore _secretStore = secretStore;

    public enum SignatureAlgorithm
    {
        RSA2048SHA512 = 1
    }

    /// <summary>
    /// Decrypts a string
    /// </summary>
    /// <param name="textToSign">Text to sign</param>
    /// <param name="keyInXMLFormat">Private key in XML format</param>
    /// <returns>Decrypted string</returns>
    public string CreateSignature(string textToSign, string keyNameInStore, int keyIndex, SignatureAlgorithm algorithm)
    {
        if (textToSign == null || textToSign.Length <= 0)
            throw new ArgumentNullException(nameof(textToSign), "textToSign cannot be null");
        if (keyNameInStore == null || keyNameInStore.Length <= 0)
            throw new ArgumentNullException(nameof(keyNameInStore), "keyNameInStore cannot be null");

        var keyInXmlFormat = _secretStore.GetKey(keyNameInStore, keyIndex);

        var signature = CreateSignatureRSA2048SHA512(textToSign, keyInXmlFormat, algorithm);
        return $"[{(int)algorithm},{keyIndex}]{signature}";
    }

    private static string CreateSignatureRSA2048SHA512(string plainText, string keyInXmlFormat, SignatureAlgorithm algorithm)
    {
        string asString;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;

            rsa.ImportParametersFromXmlString(keyInXmlFormat);

            byte[] hashBytes;
            var data = Encoding.UTF8.GetBytes(plainText);
            hashBytes = SHA512.HashData(data);

            var formatter = new RSAPKCS1SignatureFormatter(rsa);
            formatter.SetHashAlgorithm("SHA512");
            var signedAsBytes = formatter.CreateSignature(hashBytes);

            asString = ByteArrayToString(signedAsBytes);
        }

        return asString;
    }

    /// <summary>
    /// Decrypts a string
    /// </summary>
    /// <param name="textToVerify">Plain text to verify</param>
    /// <param name="textToVerify">Old Signature</param>
    /// <param name="keyInXMLFormat">Public key in XML format</param>
    /// <returns>True if signature could be verified</returns>
    public bool VerifySignature(string textToVerify, string oldSignature, string keyNameInStore)
    {
        if (textToVerify == null || textToVerify.Length <= 0)
            throw new ArgumentNullException(nameof(textToVerify), "textToVerify cannot be null");
        if (oldSignature == null || oldSignature.Length <= 0)
            throw new ArgumentNullException(nameof(oldSignature), "oldSignature cannot be null");
        if (keyNameInStore == null || keyNameInStore.Length <= 0)
            throw new ArgumentNullException(nameof(keyNameInStore), "keyNameInStore cannot be null");

        CipherTextInfo cipherTextInfo = BreakdownCipherText(oldSignature);

        if (!cipherTextInfo.Algorithm.HasValue)
            throw new InvalidOperationException("Cannot find an algorithm for encrypted string");

        var keyInXmlFormat = _secretStore.GetKey(keyNameInStore, cipherTextInfo.Index.Value);

        if (cipherTextInfo.Algorithm.Value == 1)
            return VerifySignatureRSA2048SHA512(textToVerify, cipherTextInfo.CipherText, keyInXmlFormat);
        else
            throw new InvalidOperationException($"Cannot decrypt cipher text with algorithm {cipherTextInfo.Algorithm}");
    }

    private static bool VerifySignatureRSA2048SHA512(string textToVerify, string oldSignature, string keyInXmlFormat)
    {
        bool result;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;

            byte[] hashBytes;
            var data = Encoding.UTF8.GetBytes(textToVerify);
            hashBytes = SHA512.HashData(data);

            var oldSignatureAsBytes = HexStringToByteArray(oldSignature);

            rsa.ImportParametersFromXmlString(keyInXmlFormat);
            var formatter = new RSAPKCS1SignatureDeformatter(rsa);
            formatter.SetHashAlgorithm("SHA512");
            result = formatter.VerifySignature(hashBytes, oldSignatureAsBytes);
        }

        return result;
    }

    public KeyPair GenerateKeys()
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        rsa.PersistKeyInCsp = false;

        var keyPair = new KeyPair
        {
            PrivateKey = rsa.SendParametersToXmlString(true),
            PublicKey = rsa.SendParametersToXmlString(false)
        };

        return keyPair;
    }
}
