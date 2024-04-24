using JuiceShopDotNet.Common.Cryptography.KeyStorage;
using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;
using System.Text;

namespace JuiceShopDotNet.Common.Cryptography.Hashing;

public class HashingService(ISecretStore secretStore) : BaseCryptographyProvider, IHashingService
{
    /// <summary>
    /// Hash algorithm to use
    /// </summary>
    public enum HashAlgorithm
    {
        MD5 = 1,
        SHA1 = 2,
        SHA2_256 = 3,
        SHA2_512 = 4,
        SHA3_256 = 5,
        SHA3_512 = 6,
        HMAC_SHA2_256 = 7,
        HMAC_SHA2_512 = 8
    }

    private ISecretStore _secretStore = secretStore;

    public string CreateUnsaltedHash(string plainText, HashAlgorithm algorithm)
    {
        return CreateHash(plainText, "", algorithm, null);
    }

    public string CreateSaltedHash(string plainText, string saltNameInKeyStore, int keyIndex, HashAlgorithm algorithm)
    {
        var salt = _secretStore.GetKey(saltNameInKeyStore, keyIndex);
        return CreateHash(plainText, salt, algorithm, keyIndex);
    }

    public bool MatchesHash(string plainText, string hash, string saltNameInKeyStore)
    {
        var cipherTextInfo = BreakdownCipherText(hash);

        if (!cipherTextInfo.Algorithm.HasValue)
            return false;

        var salt = _secretStore.GetKey(saltNameInKeyStore, cipherTextInfo.Index.Value);

        var plainTextHashed = CreateHash(plainText, salt, (HashAlgorithm)cipherTextInfo.Algorithm.Value, cipherTextInfo.Index);
        return plainTextHashed == hash;
    }

    private static string CreateHash(string plainText, string salt, HashAlgorithm algorithm, int? keyIndex)
    {
        var saltedBytes = Encoding.UTF8.GetBytes(string.Concat(salt, plainText));
        var plainTextAsBytes = Encoding.UTF8.GetBytes(plainText);
        var saltAsBytes = Encoding.UTF8.GetBytes(salt);
        string? hash = algorithm switch
        {
            HashAlgorithm.MD5 => HashMD5(saltedBytes),
            HashAlgorithm.SHA1 => HashSHA1(saltedBytes),
            HashAlgorithm.SHA2_256 => HashSHA2_256(saltedBytes),
            HashAlgorithm.SHA2_512 => HashSHA2_512(saltedBytes),
            HashAlgorithm.SHA3_256 => HashSHA3_256(saltedBytes),
            HashAlgorithm.SHA3_512 => HashSHA3_512(saltedBytes),
            HashAlgorithm.HMAC_SHA2_256 => HashHMACSHA2_256(plainTextAsBytes, saltAsBytes),
            HashAlgorithm.HMAC_SHA2_512 => HashHMACSHA2_512(plainTextAsBytes, saltAsBytes),
            _ => throw new NotImplementedException($"Hash algorithm {algorithm} has not been implemented"),
        };
        string prefix;

        if (keyIndex.HasValue)
            prefix = $"[{(int)algorithm},{keyIndex.Value}]";
        else
            prefix = "";

        return $"{prefix}{hash}";
    }

    private static string HashMD5(byte[] toHash)
    {
        var hashBytes = MD5.HashData(toHash);
        return ByteArrayToString(hashBytes);
    }

    private static string HashSHA1(byte[] toHash)
    {
        var hashBytes = SHA1.HashData(toHash);
        return ByteArrayToString(hashBytes);
    }

    internal static string HashSHA2_256(byte[] toHash)
    {
        var hashBytes = SHA256.HashData(toHash);
        return ByteArrayToString(hashBytes);
    }

    internal static string HashSHA2_512(byte[] toHash)
    {
        var hashBytes = SHA512.HashData(toHash);
        return ByteArrayToString(hashBytes);
    }

    internal static string HashHMACSHA2_256(byte[] toHash, byte[] key)
    {
        using var sha = new HMACSHA256(key);
        var hashBytes = sha.ComputeHash(toHash);
        return ByteArrayToString(hashBytes);
    }

    internal static string HashHMACSHA2_512(byte[] toHash, byte[] key)
    {
        using var sha = new HMACSHA512(key);
        var hashBytes = sha.ComputeHash(toHash);
        return ByteArrayToString(hashBytes);
    }

    internal static string HashSHA3_256(byte[] toHash)
    {
        var hasher = new Sha3Digest(256);
        hasher.BlockUpdate(toHash);
        var result = new byte[32]; //32 bytes = 256 bits
        hasher.DoFinal(result);
        return ByteArrayToString(result);
    }

    internal static string HashSHA3_512(byte[] toHash)
    {
        var hasher = new Sha3Digest(512);
        hasher.BlockUpdate(toHash);
        var result = new byte[64]; //64 bytes = 512 bits
        hasher.DoFinal(result);
        return ByteArrayToString(result);
    }
}
