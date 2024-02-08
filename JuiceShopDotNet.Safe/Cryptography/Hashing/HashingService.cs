using JuiceShopDotNet.Safe.Cryptography.KeyStorage;
using Microsoft.AspNetCore.Identity;

namespace JuiceShopDotNet.Safe.Cryptography.Hashing;

public class HashingService : BaseCryptographyProvider, IHashingService
{
    /// <summary>
    /// Hash algorithm to use. NOTE: Future refactoring could occur around the salt length being included in the algorithm.
    /// </summary>
    public enum HashAlgorithm
    {
        SHA2_256_Salt32 = 1,
        SHA2_512_Salt32 = 2,
        PBKDF2_SHA512_Iter100000 = 3,
        MD5_NoSalt = 4,
        SHA1_NoSalt = 5
    }

    private IKeyStore _keyStore;

    public HashingService(IKeyStore keyStore = null) //We don't need the key store if we're only hashing passwords
    {
        _keyStore = keyStore;
    }

    public string CreateHash_NoSalt(string plainText, HashAlgorithm algorithm, bool includePrefix)
    {
        if (algorithm == HashAlgorithm.PBKDF2_SHA512_Iter100000 || algorithm == HashAlgorithm.SHA2_256_Salt32 || algorithm == HashAlgorithm.SHA2_512_Salt32)
            throw new InvalidOperationException($"{algorithm} requires a salt");

        return HashWorker.CreateHash(plainText, "", algorithm, 0, includePrefix);
    }

    public string CreateSaltedHash(string plainText, string saltNameInKeyStore, int keyIndex, HashAlgorithm algorithm)
    {
        var salt = _keyStore.GetKey(saltNameInKeyStore, keyIndex);
        return HashWorker.CreateHash(plainText, salt, algorithm, keyIndex, true);
    }

    public string CreatePasswordHash(string plainText, HashAlgorithm algorithm)
    {
        var salt = Randomizer.CreateHashingSalt(algorithm);
        return HashWorker.CreateHash(plainText, salt, algorithm, null, true);
    }

    public bool MatchesHash(string plainText, string hash, string saltNameInKeyStore)
    {
        var cipherTextInfo = base.BreakdownCipherText(hash);

        if (!cipherTextInfo.Algorithm.HasValue)
            return false;

        var salt = _keyStore.GetKey(saltNameInKeyStore, cipherTextInfo.Index.Value);

        var plainTextHashed = HashWorker.CreateHash(plainText, salt, (HashAlgorithm)cipherTextInfo.Algorithm.Value, cipherTextInfo.Index, true);
        return plainTextHashed == hash;
    }

    public PasswordVerificationResult MatchesPasswordHash(string plainText, string hash)
    {
        var cipherTextInfo = base.BreakdownCipherTextAndSalt(hash);

        if (!cipherTextInfo.Algorithm.HasValue)
            return PasswordVerificationResult.Failed;

        var hashAlgorithm = (HashAlgorithm)cipherTextInfo.Algorithm.Value;
        var plainTextHashed = HashWorker.CreateHash(plainText, cipherTextInfo.Salt, hashAlgorithm, null, true);

        if (plainTextHashed == hash)
            return PasswordVerificationResult.Success;
        else
            return PasswordVerificationResult.Failed;
    }

    public static int GetSaltLength(HashAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case HashAlgorithm.SHA2_256_Salt32:
            case HashAlgorithm.SHA2_512_Salt32:
            case HashAlgorithm.PBKDF2_SHA512_Iter100000:
                return 32;
            case HashAlgorithm.MD5_NoSalt:
            case HashAlgorithm.SHA1_NoSalt:
                return 0;
            default:
                throw new NotImplementedException($"Unknown salt length for algorithm {algorithm}");
        }
    }
}
