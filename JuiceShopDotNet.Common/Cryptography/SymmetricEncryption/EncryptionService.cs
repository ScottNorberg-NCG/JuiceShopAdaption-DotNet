using JuiceShopDotNet.Common.Cryptography.KeyStorage;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;

namespace JuiceShopDotNet.Common.Cryptography.SymmetricEncryption;

public class EncryptionService(ISecretStore secretStore) : BaseCryptographyProvider, IEncryptionService
{
    private const EncryptionAlgorithm DEFAULT_ALGORITHM = EncryptionAlgorithm.AES256;

    public enum EncryptionAlgorithm
    {
        AES128 = 1,
        AES256 = 2,
        Twofish128 = 3,
        Twofish256 = 4
    }

    public static int GetKeyLengthForAlgorithm(EncryptionAlgorithm algorithm)
    {
        return algorithm switch
        {
            EncryptionAlgorithm.AES128 or EncryptionAlgorithm.Twofish128 => 16,
            EncryptionAlgorithm.AES256 or EncryptionAlgorithm.Twofish256 => 32,
            _ => throw new NotImplementedException($"Cannot find key length for {algorithm} algorithm"),
        };
    }

    public static int GetIVLengthForAlgorithm(EncryptionAlgorithm algorithm)
    {
        return algorithm switch
        {
            EncryptionAlgorithm.AES128 or EncryptionAlgorithm.AES256 or EncryptionAlgorithm.Twofish128 or EncryptionAlgorithm.Twofish256 => 16,
            _ => throw new NotImplementedException($"Cannot find key length for {algorithm} algorithm"),
        };
    }

    private ISecretStore _secretStore = secretStore;

    public string Encrypt(string toEncrypt, string encryptionKeyName, int keyIndex)
    {
        return Encrypt(toEncrypt, encryptionKeyName, keyIndex, DEFAULT_ALGORITHM);
    }

    public string Encrypt(string plainText, string encryptionKeyName, int keyIndex, EncryptionAlgorithm algorithm)
    {
        // Check arguments.
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException(nameof(plainText),"PlainText cannot be empty");
        if (encryptionKeyName == null || encryptionKeyName.Length <= 0)
            throw new ArgumentNullException(nameof(encryptionKeyName),"Key name cannot be empty");

        var keyValue = _secretStore.GetKey(encryptionKeyName, keyIndex);
        string? encrypted = algorithm switch
        {
            EncryptionAlgorithm.AES128 or EncryptionAlgorithm.AES256 => EncryptAES(plainText, keyValue, algorithm),
            EncryptionAlgorithm.Twofish128 or EncryptionAlgorithm.Twofish256 => EncryptTwofish(plainText, keyValue, algorithm),
            _ => throw new NotImplementedException($"Cannot find implementation for algorithm {algorithm}"),
        };
        return $"[{(int)algorithm},{keyIndex}]{encrypted}";
    }

    private static string EncryptAES(string plainText, string key, EncryptionAlgorithm algorithm)
    {
        byte[] encrypted;
        var keyBytes = HexStringToByteArray(key);
        var iv = Randomizer.CreateIV(algorithm);
        var ivBytes = HexStringToByteArray(iv);

        using (Aes aes = Aes.Create())
        {
            aes.Key = keyBytes;
            aes.Padding = PaddingMode.ANSIX923;
            aes.Mode = CipherMode.CFB;
            aes.IV = ivBytes;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            // Create the streams used for encryption.
            using MemoryStream memStream = new();
            using CryptoStream cryptStream = new(memStream, encryptor, CryptoStreamMode.Write);
            using (StreamWriter writer = new(cryptStream))
            {
                writer.Write(plainText);
            }

            encrypted = memStream.ToArray();
        }

        var asString = ByteArrayToString(encrypted);

        return $"{iv}{asString}";
    }

    private static string EncryptTwofish(string plainText, string key, EncryptionAlgorithm algorithm)
    {
        var cipher = new TwofishEngine();

        IBlockCipherMode mode = new CfbBlockCipher(cipher, 128);

        //var padding = new Pkcs7Padding();

        var paddedCipher = new BufferedBlockCipher(mode);

        var keyAsBytes = HexStringToByteArray(key);
        var keyParam = new KeyParameter(keyAsBytes);
        var iv = Randomizer.CreateRandomByteArray(GetIVLengthForAlgorithm(algorithm));
        var paramWithIV = new ParametersWithIV(keyParam, iv);

        paddedCipher.Init(true, paramWithIV);

        var plainTextAsBytes = Encoding.UTF8.GetBytes(plainText);

        var encryptedAsBytes = paddedCipher.DoFinal(plainTextAsBytes);
        var encrypted = ByteArrayToString(encryptedAsBytes);

        return $"{ByteArrayToString(iv)}{encrypted}";
    }

    public string Decrypt(string toDecrypt, string encryptionKeyName)
    {
        if (toDecrypt == null || toDecrypt.Length <= 0)
            throw new ArgumentNullException(nameof(toDecrypt), "string to decrypt cannot be null");
        if (encryptionKeyName == null || encryptionKeyName.Length <= 0)
            throw new ArgumentNullException(nameof(encryptionKeyName), "encryptionKeyName cannot be null");

        var cipherTextInfo = BreakdownCipherText(toDecrypt);
        var keyValue = _secretStore.GetKey(encryptionKeyName, cipherTextInfo.Index.Value);

        if (!cipherTextInfo.Algorithm.HasValue)
            throw new InvalidOperationException("Cannot find an algorithm for encrypted string");

        var algorithm = (EncryptionAlgorithm)cipherTextInfo.Algorithm.Value;
        var ivLength = GetIVLengthForAlgorithm(algorithm) * 2;

        var ivString = cipherTextInfo.CipherText[..ivLength];
        var cipherNoIV = cipherTextInfo.CipherText[ivLength..];

        if (algorithm == EncryptionAlgorithm.AES128 || algorithm == EncryptionAlgorithm.AES256)
            return DecryptStringAES(cipherNoIV, keyValue, ivString);
        else if (algorithm == EncryptionAlgorithm.Twofish128 || algorithm == EncryptionAlgorithm.Twofish256)
            return DecryptTwofish(cipherNoIV, keyValue, ivString, algorithm);
        else
            throw new InvalidOperationException($"Cannot decrypt cipher text with algorithm {cipherTextInfo.Algorithm}");
    }

    private static string DecryptStringAES(string cipherText, string key, string iv)
    {
        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;
        var keyBytes = HexStringToByteArray(key);

        var ivBytes = HexStringToByteArray(iv);
        var cipherBytes = HexStringToByteArray(cipherText);

        using (Aes aes = Aes.Create())
        {
            aes.Key = keyBytes;
            aes.Padding = PaddingMode.ANSIX923;
            aes.Mode = CipherMode.CFB;
            aes.IV = ivBytes;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            // Create the streams used for decryption.
            using MemoryStream memStream = new(cipherBytes);
            using CryptoStream cryptStream = new(memStream, decryptor, CryptoStreamMode.Read);
            using StreamReader reader = new(cryptStream);
            plaintext = reader.ReadToEnd();
        }

        return plaintext;
    }

    private static string DecryptTwofish(string ciphertext, string key, string iv, EncryptionAlgorithm algorithm)
    {
        var ivBytes = HexStringToByteArray(iv);
        var cipherBytes = HexStringToByteArray(ciphertext);

        var cipher = new TwofishEngine();

        IBlockCipherMode mode = new CfbBlockCipher(cipher, 128);

        //var padding = new Pkcs7Padding();

        var paddedCipher = new BufferedBlockCipher(mode);

        var keyAsBytes = HexStringToByteArray(key);
        var keyParam = new KeyParameter(keyAsBytes);
        var paramWithIV = new ParametersWithIV(keyParam, ivBytes);

        paddedCipher.Init(false, paramWithIV);

        var decryptedAsBytes = paddedCipher.DoFinal(cipherBytes);

        return Encoding.UTF8.GetString(decryptedAsBytes);
    }
}
