using JuiceShopDotNet.Safe.Cryptography.KeyStorage;
using System.Security.Cryptography;

namespace JuiceShopDotNet.Safe.Cryptography.SymmetricEncryption;

public class EncryptionService : BaseCryptographyProvider, IEncryptionService
{
    public enum EncryptionAlgorithm
    {
        AES128 = 1,
        AES256 = 2
    }

    public static int GetKeyLengthForAlgorithm(EncryptionAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case EncryptionAlgorithm.AES128:
                return 16;
            case EncryptionAlgorithm.AES256:
                return 32;
            default:
                throw new NotImplementedException($"Cannot find key length for {algorithm} algorithm");
        }
    }

    public static int GetIVLengthForAlgorithm(EncryptionAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case EncryptionAlgorithm.AES128:
                return 16;
            case EncryptionAlgorithm.AES256:
                return 16;
            default:
                throw new NotImplementedException($"Cannot find key length for {algorithm} algorithm");
        }
    }

    private IKeyStore _keyStore;
    public EncryptionService(IKeyStore keyStore)
    {
        _keyStore = keyStore;
    }

    public string Encrypt(string toEncrypt, string encryptionKeyName, int keyIndex)
    {
        return Encrypt(toEncrypt, encryptionKeyName, keyIndex, EncryptionAlgorithm.AES128);
    }

    public string Encrypt(string plainText, string encryptionKeyName, int keyIndex, EncryptionAlgorithm algorithm)
    {
        // Check arguments.
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("PlainText cannot be empty");
        if (encryptionKeyName == null || encryptionKeyName.Length <= 0)
            throw new ArgumentNullException("Key name cannot be empty");

        var keyValue = _keyStore.GetKey(encryptionKeyName, keyIndex);

        switch (algorithm)
        {
            case EncryptionAlgorithm.AES128:
            case EncryptionAlgorithm.AES256:
                return EncryptAES(plainText, keyValue, keyIndex, algorithm);
            default:
                throw new NotImplementedException($"Cannot find implementation for algorithm {algorithm}");
        }
    }

    private string EncryptAES(string plainText, string key, int keyIndex, EncryptionAlgorithm algorithm)
    {
        byte[] encrypted;
        var keyBytes = HexStringToByteArray(key);
        var iv = Randomizer.CreateIV(algorithm);
        var ivBytes = HexStringToByteArray(iv);

        // Create an Rijndael object
        // with the specified key and IV.
        using (Rijndael rijAlg = Rijndael.Create())
        {
            rijAlg.Key = keyBytes;
            rijAlg.Padding = PaddingMode.ANSIX923;
            rijAlg.Mode = CipherMode.CFB;
            rijAlg.IV = ivBytes;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        var asString = ByteArrayToString(encrypted);

        return $"[{(int)algorithm},{keyIndex}]{iv}{asString}";
    }

    public string Decrypt(string toDecrypt, string encryptionKeyName)
    {
        if (toDecrypt == null || toDecrypt.Length <= 0)
            throw new ArgumentNullException("toDecrypt");
        if (encryptionKeyName == null || encryptionKeyName.Length <= 0)
            throw new ArgumentNullException("encryptionKeyName");

        var cipherTextInfo = BreakdownCipherText(toDecrypt);
        var keyValue = _keyStore.GetKey(encryptionKeyName, cipherTextInfo.Index.Value);

        if (!cipherTextInfo.Algorithm.HasValue)
            throw new InvalidOperationException("Cannot find an algorithm for encrypted string");

        if (cipherTextInfo.Algorithm.Value == 1 || cipherTextInfo.Algorithm.Value == 2)
        {
            var algorithm = (EncryptionAlgorithm)cipherTextInfo.Algorithm.Value;
            var ivLength = GetIVLengthForAlgorithm(algorithm) * 2;
            return DecryptStringAES(cipherTextInfo.CipherText, keyValue, ivLength);
        }
        else
            throw new InvalidOperationException($"Cannot decrypt cipher text with algorithm {cipherTextInfo.Algorithm}");
    }

    private string DecryptStringAES(string cipherText, string Key, int ivLengthInHex)
    {
        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;
        var keyBytes = HexStringToByteArray(Key);

        var ivString = cipherText.Substring(0, ivLengthInHex);
        var ivBytes = HexStringToByteArray(ivString);

        var cipherNoIV = cipherText.Substring(ivLengthInHex, cipherText.Length - ivLengthInHex);
        var cipherBytes = HexStringToByteArray(cipherNoIV);

        // Create an Rijndael object
        // with the specified key and IV.
        using (Rijndael rijAlg = Rijndael.Create())
        {
            rijAlg.Key = keyBytes;
            rijAlg.Padding = PaddingMode.ANSIX923;
            rijAlg.Mode = CipherMode.CFB;
            rijAlg.IV = ivBytes;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
            //ICryptoTransform decryptor = rijAlg.CreateDecryptor();

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }
}
