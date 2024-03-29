﻿using JuiceShopDotNet.Common.Cryptography.AsymmetricEncryption;
using System.Text;
using JuiceShopDotNet.Safe.Cryptography;
using System.Text.Json.Serialization;
using System.Text.Json;

namespace JuiceShopDotNet.Safe.Data.EncryptedDataStore;

public class RemoteSensitiveDataStore : IRemoteSensitiveDataStore
{
    private readonly IConfiguration _config;
    private readonly ISignatureService _signatureService;

    public RemoteSensitiveDataStore(IConfiguration config, ISignatureService signatureService)
    { 
        _config = config;
        _signatureService = signatureService;
    }

    public EncryptedCreditApplication GetCreditApplication(int id)
    {
        var data = new { id };
        var response = PostData(data, "GetCreditApplication");

        if (response.IsSuccessStatusCode)
        {
            var options = new JsonSerializerOptions();
            options.PropertyNameCaseInsensitive = true;
            return JsonSerializer.Deserialize<EncryptedCreditApplication>(response.Content.ReadAsStringAsync().Result, options);
        }
        else
        {
            //TODO: Log this
            return null;
        }
    }

    public EncryptedJuiceShopUser GetJuiceShopUser(int id)
    {
        var data = new { id };
        var response = PostData(data, "GetJuiceShopUser");

        if (response.IsSuccessStatusCode)
        {
            var options = new JsonSerializerOptions();
            options.PropertyNameCaseInsensitive = true;
            return JsonSerializer.Deserialize<EncryptedJuiceShopUser>(response.Content.ReadAsStringAsync().Result, options);
        }
        else
        {
            //TODO: Log this
            return null;
        }
    }

    public bool SaveCreditApplication(EncryptedCreditApplication application)
    {
        var response = PostData(application, "SaveCreditApplication");
        return response.IsSuccessStatusCode;
    }

    public bool SaveJuiceShopUser(EncryptedJuiceShopUser user)
    {
        var response = PostData(user, "SaveJuiceShopUser");
        return response.IsSuccessStatusCode;
    }

    private HttpResponseMessage PostData(object data, string endpoint)
    {
        try
        {
            var objectAsString = System.Text.Json.JsonSerializer.Serialize(data);
            var timestamp = DateTime.UtcNow;

            var signature = _signatureService.CreateSignature($"{timestamp}|{objectAsString}", KeyNames.ApiPrivateKey, 1, SignatureService.SignatureAlgorithm.RSA2048SHA512);

            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Timestamp", timestamp.ToString());
            client.DefaultRequestHeaders.Add("Signature", signature);

            var content = new StringContent(objectAsString, Encoding.UTF8, "application/json");
            return client.PostAsync(new Uri(_config.GetValue<string>("EncryptionApiUrl") + "/Vault/" + endpoint), content).Result;
        }
        catch (Exception e)
        {
            //TODO: Log this
            return null;
        }
    }
}
