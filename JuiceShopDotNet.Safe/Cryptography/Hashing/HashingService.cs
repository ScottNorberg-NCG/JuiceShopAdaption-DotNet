using JuiceShopDotNet.Safe.Cryptography.KeyStorage;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using System.Text;

namespace JuiceShopDotNet.Safe.Cryptography.Hashing;

public class HashingService : BaseCryptographyProvider, IHashingService
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
        SHA3_512 = 6
    }

    private IKeyStore _keyStore;

    public HashingService(IKeyStore keyStore)
    {
        _keyStore = keyStore;
    }

    public string CreateUnsaltedHash(string plainText, HashAlgorithm algorithm, bool includePrefix)
    {
        return CreateHash(plainText, "", algorithm, null);
    }

    public string CreateSaltedHash(string plainText, string saltNameInKeyStore, int keyIndex, HashAlgorithm algorithm)
    {
        var salt = _keyStore.GetKey(saltNameInKeyStore, keyIndex);
        return CreateHash(plainText, salt, algorithm, keyIndex);
    }

    public bool MatchesHash(string plainText, string hash, string saltNameInKeyStore)
    {
        var cipherTextInfo = base.BreakdownCipherText(hash);

        if (!cipherTextInfo.Algorithm.HasValue)
            return false;

        var salt = _keyStore.GetKey(saltNameInKeyStore, cipherTextInfo.Index.Value);

        var plainTextHashed = CreateHash(plainText, salt, (HashAlgorithm)cipherTextInfo.Algorithm.Value, cipherTextInfo.Index);
        return plainTextHashed == hash;
    }

    private static string CreateHash(string plainText, string salt, HashAlgorithm algorithm, int? keyIndex)
    {
        var toHash = Encoding.UTF8.GetBytes(string.Concat(salt, plainText));
        var hash = "";

        switch (algorithm)
        { 
            case HashAlgorithm.MD5:
                hash = HashMD5(toHash);
                break;
            case HashAlgorithm.SHA1:
                hash = HashSHA1(toHash);
                break;
            case HashAlgorithm.SHA2_256:
                hash = HashSHA2_256(toHash);
                break;
            case HashAlgorithm.SHA2_512:
                hash = HashSHA2_512(toHash);
                break;
            case HashAlgorithm.SHA3_256:
                hash = HashSHA3_256(toHash);
                break;
            case HashAlgorithm.SHA3_512:
                hash = HashSHA3_512(toHash);
                break;
            default:
                throw new NotImplementedException($"Hash algorithm {algorithm} has not been implemented");
        }

        string prefix;

        if (!keyIndex.HasValue)
            prefix = "";
        else
            prefix = $"[{(int)algorithm},{keyIndex.Value}]";

        return $"{prefix}{hash}";
    }

    private static string HashMD5(byte[] toHash)
    {
        using (MD5 md5 = MD5.Create())
        {
            var hashBytes = md5.ComputeHash(toHash);
            return ByteArrayToString(hashBytes);
        }
    }

    private static string HashSHA1(byte[] toHash)
    {
        using (SHA1 sha1 = SHA1.Create())
        {
            var hashBytes = sha1.ComputeHash(toHash);
            return ByteArrayToString(hashBytes);
        }
    }

    internal static string HashSHA2_256(byte[] toHash)
    {
        using (var sha = SHA256.Create())
        {
            var hashBytes = sha.ComputeHash(toHash);
            return ByteArrayToString(hashBytes);
        }
    }

    internal static string HashSHA2_512(byte[] toHash)
    {
        using (SHA512 sha = SHA512.Create())
        {
            var hashBytes = sha.ComputeHash(toHash);
            return ByteArrayToString(hashBytes);
        }
    }

    internal static string HashSHA3_256(byte[] toHash)
    {
        using (var sha = SHA3_256.Create())
        {
            var hashBytes = sha.ComputeHash(toHash);
            return ByteArrayToString(hashBytes);
        }
    }

    internal static string HashSHA3_512(byte[] toHash)
    {
        using (var sha = SHA3_512.Create())
        {
            var hashBytes = sha.ComputeHash(toHash);
            return ByteArrayToString(hashBytes);
        }
    }
}
