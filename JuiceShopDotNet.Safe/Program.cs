using JuiceShopDotNet.Common.Cryptography.AsymmetricEncryption;
using JuiceShopDotNet.Common.Cryptography.Hashing;
using JuiceShopDotNet.Common.Cryptography.KeyStorage;
using JuiceShopDotNet.Safe.Auth;
using JuiceShopDotNet.Safe.Cryptography;
using JuiceShopDotNet.Safe.Data;
using JuiceShopDotNet.Safe.Data.EncryptedDataStore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<JuiceShopUser>(options => options.SignIn.RequireConfirmedAccount = true);
    //.AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();

builder.Services.AddSingleton<IHashingService, HashingService>();
builder.Services.AddSingleton<ISecretStore, ForDemoPurposesOnlySecretStore>();
builder.Services.AddSingleton<IRemoteSensitiveDataStore, RemoteSensitiveDataStore>();
builder.Services.AddSingleton<ISignatureService, SignatureService>();

builder.Services.RemoveAll<IUserStore<JuiceShopUser>>();
builder.Services.AddSingleton<IUserStore<JuiceShopUser>, UserStore>();

builder.Services.ConfigureApplicationCookie(options => {
    options.LoginPath = "/Auth/MyAccount/Login";
    options.LogoutPath = "/Auth/MyAccount/Login";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
