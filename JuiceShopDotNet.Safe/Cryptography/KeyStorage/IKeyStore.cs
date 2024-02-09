namespace JuiceShopDotNet.Safe.Cryptography.KeyStorage;

public interface IKeyStore
{
    /// <summary>
    /// Gets the full key from the key store.
    /// </summary>
    /// <returns>String representation of the key</returns>
    string GetKey(string keyName, int keyIndex);
}
