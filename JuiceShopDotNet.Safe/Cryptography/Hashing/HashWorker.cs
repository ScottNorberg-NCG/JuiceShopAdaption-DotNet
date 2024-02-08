using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

namespace JuiceShopDotNet.Safe.Cryptography.Hashing;

internal class HashWorker : BaseCryptographyProvider
{
    public static string CreateHash(string plainText, string salt, HashingService.HashAlgorithm algorithm, int? keyIndex, bool includePrefix)
    {
        var hash = "";

        switch (algorithm)
        {
            case HashingService.HashAlgorithm.SHA2_256_Salt32:
                hash = HashSHA2_256(plainText, salt);
                break;
            case HashingService.HashAlgorithm.SHA2_512_Salt32:
                hash = HashSHA2_512(plainText, salt);
                break;
            case HashingService.HashAlgorithm.PBKDF2_SHA512_Iter100000:
                hash = PBKDF2_SHA512_Iter100000(plainText, salt);
                break;   
            case HashingService.HashAlgorithm.MD5_NoSalt:
                hash = MD5_NoSalt(plainText);
                break;
            case HashingService.HashAlgorithm.SHA1_NoSalt:
                hash = SHA1_NoSalt(plainText);
                break;
            default:
                throw new NotImplementedException($"Hash algorithm {algorithm} has not been implemented");
        }

        string prefix;

        if (!includePrefix)
            prefix = "";
        else
        {
            if (!keyIndex.HasValue)
                prefix = $"[{(int)algorithm}]";
            else
                prefix = $"[{(int)algorithm},{keyIndex.Value}]";
        }

        //This is a bit awkward checking for the keyIndex twice - refactor when a better solution is found
        if (!keyIndex.HasValue)
            return $"{prefix}{salt}{hash}";
        else
            return $"{prefix}{hash}";
    }

    internal static string HashSHA2_256(string plainText, string salt)
    {
        var fullText = string.Concat(salt, plainText);
        var data = Encoding.UTF8.GetBytes(fullText);

        using (var sha = SHA256.Create())
        {
            var hashBytes = sha.ComputeHash(data);
            return ByteArrayToString(hashBytes);
        }
    }

    internal static string HashSHA2_512(string plainText, string salt)
    {
        var fullText = string.Concat(salt, plainText);
        var data = Encoding.UTF8.GetBytes(fullText);

        using (SHA512 sha = new SHA512Managed())
        {
            var hashBytes = sha.ComputeHash(data);
            return ByteArrayToString(hashBytes);
        }
    }

    internal static string PBKDF2_SHA512_Iter100000(string plainText, string salt)
    {
        byte[] saltAsBytes = HexStringToByteArray(salt);
        byte[] hashed = KeyDerivation.Pbkdf2(plainText, saltAsBytes, KeyDerivationPrf.HMACSHA512, 100000, 512 / 8);
        return ByteArrayToString(hashed);
    }

    internal static string MD5_NoSalt(string plainText)
    {
        var data = Encoding.UTF8.GetBytes(plainText);

        using (MD5 md5 = MD5.Create())
        {
            var hashBytes = md5.ComputeHash(data);
            return ByteArrayToString(hashBytes);
        }
    }

    internal static string SHA1_NoSalt(string plainText)
    {
        var data = Encoding.UTF8.GetBytes(plainText);

        using (SHA1 sha1 = SHA1.Create())
        {
            var hashBytes = sha1.ComputeHash(data);
            return ByteArrayToString(hashBytes);
        }
    }
}
