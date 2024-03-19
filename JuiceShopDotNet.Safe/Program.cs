using JuiceShopDotNet.Common.Cryptography.AsymmetricEncryption;
using JuiceShopDotNet.Common.Cryptography.Hashing;
using JuiceShopDotNet.Common.Cryptography.KeyStorage;
using JuiceShopDotNet.Safe.Auth;
using JuiceShopDotNet.Safe.Cryptography;
using JuiceShopDotNet.Safe.Cryptography.Hashing;
using JuiceShopDotNet.Safe.CSRF;
using JuiceShopDotNet.Safe.Data;
using JuiceShopDotNet.Safe.Data.EncryptedDataStore;
using JuiceShopDotNet.Safe.Emails;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection.KeyManagement.Internal;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddIdentity<JuiceShopUser, SystemRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    options.User.RequireUniqueEmail = true;
    options.Tokens.AuthenticatorIssuer = "email";
    options.Tokens.AuthenticatorTokenProvider = "email";
    options.Tokens.EmailConfirmationTokenProvider = "email";
    options.Tokens.PasswordResetTokenProvider = "email";
    options.Tokens.PasswordResetTokenProvider = "email";
    options.Tokens.ChangePhoneNumberTokenProvider = "email";
})
    .AddTokenProvider<CustomTokenProvider>("email");

builder.Services.AddAuthentication();

builder.Services.AddSingleton<IRoleStore<SystemRole>, CustomRoleStore>();
//builder.Services.AddDefaultIdentity<JuiceShopUser>(options =>
//{
//    options.SignIn.RequireConfirmedAccount = true;
//    options.User.RequireUniqueEmail = true;
//    //options.Tokens.EmailConfirmationTokenProvider = "email";
//    //options.Tokens.AuthenticatorTokenProvider = "email";
//    //options.Tokens.AuthenticatorIssuer = "email";
//    //options.Tokens.PasswordResetTokenProvider = "email";
//})
//    .AddTokenProvider<EmailTokenProvider<JuiceShopUser>>("email");

//.AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

builder.Services.AddSingleton<IHashingService, HashingService>();
builder.Services.AddSingleton<ISecretStore, ForDemoPurposesOnlySecretStore>();
builder.Services.AddSingleton<IRemoteSensitiveDataStore, RemoteSensitiveDataStore>();
builder.Services.AddSingleton<ISignatureService, SignatureService>();

builder.Services.RemoveAll<IUserStore<JuiceShopUser>>();
builder.Services.AddSingleton<IUserStore<JuiceShopUser>, CustomUserStore>();

builder.Services.RemoveAll<IPasswordHasher<JuiceShopUser>>();
builder.Services.AddSingleton<IPasswordHasher<JuiceShopUser>, PasswordHashingService>();

builder.Services.RemoveAll<SignInManager<JuiceShopUser>>();
builder.Services.AddScoped<SignInManager<JuiceShopUser>, CustomSignInManager>();

builder.Services.RemoveAll<UserManager<JuiceShopUser>>();
builder.Services.AddScoped<UserManager<JuiceShopUser>, CustomUserManager>();

builder.Services.RemoveAll<IAntiforgeryAdditionalDataProvider>();
builder.Services.AddSingleton<IAntiforgeryAdditionalDataProvider, AntiforgeryAdditionalDataProvider>();

builder.Services.RemoveAll<IEmailSender>();
builder.Services.RemoveAll<IEmailSender<JuiceShopUser>>();
builder.Services.AddSingleton<IEmailSender, EmailSimulatorToFile>();
builder.Services.AddSingleton<IEmailSender<JuiceShopUser>, EmailSimulatorToFile>();

builder.Services.ConfigureApplicationCookie(options => {
    options.AccessDeniedPath = "/Auth/MyAccount/AccessDenied";
    options.LoginPath = "/Auth/MyAccount/Login";
    options.LogoutPath = "/Auth/MyAccount/Login";
    
    options.Events = new CustomCookieAuthenticationEvents();
});

builder.Services.Configure<IdentityOptions>(options => { 
    options.User.RequireUniqueEmail = true;

    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 15;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
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
    pattern: "{controller=Home}/{action=Index}/{id?}").RequireAuthorization();

app.MapRazorPages().RequireAuthorization();

app.Run();
