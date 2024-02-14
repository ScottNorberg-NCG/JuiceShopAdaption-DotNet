using System.Security.Cryptography;
using System.Text;

namespace JuiceShopDotNet.Safe.Cryptography.AsymmetricEncryption;

public class SignatureService : BaseCryptographyProvider, ISignatureService
{
    public enum SignatureAlgorithm
    {
        RSA2048SHA512 = 1
    }

    public SignatureService()
    {
    }

    /// <summary>
    /// Decrypts a string
    /// </summary>
    /// <param name="textToSign">Text to sign</param>
    /// <param name="keyInXMLFormat">Private key in XML format</param>
    /// <returns>Decrypted string</returns>
    public string CreateSignatureKeyProvided(string textToSign, string keyInXMLFormat, SignatureAlgorithm algorithm)
    {
        if (textToSign == null || textToSign.Length <= 0)
            throw new ArgumentNullException("textToSign cannot be null");
        if (keyInXMLFormat == null || keyInXMLFormat.Length <= 0)
            throw new ArgumentNullException("keyInXMLFormat cannot be null");

        return CreateSignatureRSA2048SHA512(textToSign, keyInXMLFormat, algorithm);
    }

    private string CreateSignatureRSA2048SHA512(string plainText, string keyInXMLFormat, SignatureAlgorithm algorithm)
    {
        string asString;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;

            rsa.ImportParametersFromXmlString(keyInXMLFormat);

            byte[] hashBytes;

            using (SHA512 sha = SHA512.Create())
            {
                var data = Encoding.UTF8.GetBytes(plainText);
                hashBytes = sha.ComputeHash(data);
            }

            var formatter = new RSAPKCS1SignatureFormatter(rsa);
            formatter.SetHashAlgorithm("SHA512");
            var signedAsBytes = formatter.CreateSignature(hashBytes);

            asString = ByteArrayToString(signedAsBytes);
        }

        return $"[{(int)algorithm}]{asString}";
    }

    /// <summary>
    /// Decrypts a string
    /// </summary>
    /// <param name="textToVerify">Plain text to verify</param>
    /// <param name="textToVerify">Old Signature</param>
    /// <param name="keyInXMLFormat">Public key in XML format</param>
    /// <returns>True if signature could be verified</returns>
    public bool VerifySignatureKeyProvided(string textToVerify, string oldSignature, string keyInXMLFormat)
    {
        if (textToVerify == null || textToVerify.Length <= 0)
            throw new ArgumentNullException("textToVerify cannot be null");
        if (oldSignature == null || oldSignature.Length <= 0)
            throw new ArgumentNullException("oldSignature cannot be null");
        if (keyInXMLFormat == null || keyInXMLFormat.Length <= 0)
            throw new ArgumentNullException("keyInXMLFormat");

        CipherTextInfo cipherTextInfo = BreakdownCipherText(oldSignature);

        if (!cipherTextInfo.Algorithm.HasValue)
            throw new InvalidOperationException("Cannot find an algorithm for encrypted string");

        if (cipherTextInfo.Algorithm.Value == 1)
            return VerifySignatureRSA2048SHA512(textToVerify, cipherTextInfo.CipherText, keyInXMLFormat);
        else
            throw new InvalidOperationException($"Cannot decrypt cipher text with algorithm {cipherTextInfo.Algorithm}");
    }

    private bool VerifySignatureRSA2048SHA512(string textToVerify, string oldSignature, string keyInXMLFormat)
    {
        bool result;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;

            byte[] hashBytes;

            using (SHA512 sha = SHA512.Create())
            {
                var data = Encoding.UTF8.GetBytes(textToVerify);
                hashBytes = sha.ComputeHash(data);
            }

            var oldSignatureAsBytes = HexStringToByteArray(oldSignature);

            rsa.ImportParametersFromXmlString(keyInXMLFormat);
            var formatter = new RSAPKCS1SignatureDeformatter(rsa);
            formatter.SetHashAlgorithm("SHA512");
            result = formatter.VerifySignature(hashBytes, oldSignatureAsBytes);
        }

        return result;
    }

    public KeyPair GenerateKeys()
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;

            var keyPair = new KeyPair();

            keyPair.PrivateKey = rsa.SendParametersToXmlString(true);
            keyPair.PublicKey = rsa.SendParametersToXmlString(false);

            return keyPair;
        }
    }
}
