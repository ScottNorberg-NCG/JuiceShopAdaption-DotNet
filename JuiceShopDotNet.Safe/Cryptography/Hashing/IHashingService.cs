using Microsoft.AspNetCore.Identity;

namespace JuiceShopDotNet.Safe.Cryptography.Hashing;

public interface IHashingService
{
    string CreateHash_NoSalt(string plainText, HashingService.HashAlgorithm algorithm, bool includePrefix);
    string CreateSaltedHash(string plainText, string saltNameInKeyStore, int keyIndex, HashingService.HashAlgorithm algorithm);
    string CreatePasswordHash(string plainText, HashingService.HashAlgorithm algorithm);
    bool MatchesHash(string plainText, string hash, string saltNameInKeyStore);
    PasswordVerificationResult MatchesPasswordHash(string plainText, string hash);
}
