using JuiceShopDotNet.Common.Cryptography.Hashing;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace JuiceShopDotNet.Safe.Data.ValueConverters;

public class SSNConverter : ValueConverter<string, string>
{
    public SSNConverter(string encryptionKeyName, string hashSaltName, IHashingService hasher) : base(v => ToDatabase(v, hasher), v => FromDatabase(v)) { }

    public static string ToDatabase(string value, IHashingService hasher)
    {
        return hasher.CreateUnsaltedHash(value, HashingService.HashAlgorithm.SHA1);
    }

    public static string FromDatabase(string value) 
    { 
        return value;
    }
}
