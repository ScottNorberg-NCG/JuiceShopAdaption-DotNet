using JuiceShopDotNet.API.Cryptography;
using JuiceShopDotNet.API.Data;
using JuiceShopDotNet.Common.Cryptography.AsymmetricEncryption;
using JuiceShopDotNet.Common.Cryptography.KeyStorage;
using JuiceShopDotNet.Common.Cryptography.SymmetricEncryption;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<DatabaseContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddSingleton<ISignatureService, SignatureService>();
builder.Services.AddSingleton<ISecretStore, ForDemoPurposesOnlySecretStore>();
builder.Services.AddSingleton<IEncryptionService, EncryptionService>();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
