using JuiceShopDotNet.Safe.Cryptography.Hashing;
using JuiceShopDotNet.Safe.Cryptography.SymmetricEncryption;
using System.Security.Cryptography;

namespace JuiceShopDotNet.Safe.Cryptography;

public static class Randomizer
{
    public static string CreateIV(EncryptionService.EncryptionAlgorithm algorithm)
    {
        var length = EncryptionService.GetIVLengthForAlgorithm(algorithm);
        return CreateRandomString(length);
    }

    public static string CreateRandomString(int length)
    {
        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        byte[] buffer = new byte[length];

        rng.GetBytes(buffer);
        return BitConverter.ToString(buffer).Replace("-", "");
    }

    public static byte[] CreateRandomByteArray(int length)
    {
        RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        byte[] buffer = new byte[length];

        rng.GetBytes(buffer);
        return buffer;
    }
}
