using Microsoft.AspNetCore.Identity;

namespace JuiceShopDotNet.Safe.Cryptography.Hashing;

public interface IHashingService
{
    string CreateUnsaltedHash(string plainText, HashingService.HashAlgorithm algorithm, bool includePrefix);
    string CreateSaltedHash(string plainText, string saltNameInKeyStore, int keyIndex, HashingService.HashAlgorithm algorithm);
    bool MatchesHash(string plainText, string hash, string saltNameInKeyStore);
}
