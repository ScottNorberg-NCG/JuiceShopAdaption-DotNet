using JuiceShopDotNet.Safe.Cryptography;
using JuiceShopDotNet.Safe.Cryptography.KeyStorage;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JuiceShopDotNet.Safe.Tests.MockObjects;

internal class MockKeyStore : ISecretStore
{
    private struct KeyInfo
    {
        public int KeyIndex { get; set; }
        public string KeyName { get; set; }
        public string KeyValue { get; set; }
    }

    private List<KeyInfo> _generatedKeys = new List<KeyInfo>();

    public int CreateKey(string keyName, int keyLength)
    {
        var keyInfo = new KeyInfo() { KeyName = keyName };
        keyInfo.KeyIndex = _generatedKeys.Count(k => k.KeyName == keyName) + 1;
        keyInfo.KeyValue = Randomizer.CreateRandomString(keyLength);

        _generatedKeys.Add(keyInfo);

        return keyInfo.KeyIndex;
    }

    public string GetKey(string keyName, int keyIndex)
    {
        return _generatedKeys.Single(k => k.KeyName == keyName && k.KeyIndex == keyIndex).KeyValue;
    }
}
