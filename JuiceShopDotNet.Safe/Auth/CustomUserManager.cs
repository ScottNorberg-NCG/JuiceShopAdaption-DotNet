using JuiceShopDotNet.Safe.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Diagnostics.CodeAnalysis;

namespace JuiceShopDotNet.Safe.Auth;

public class CustomUserManager : UserManager<JuiceShopUser>
{
    public CustomUserManager(IUserStore<JuiceShopUser> store, 
                             IOptions<IdentityOptions> optionsAccessor, 
                             IPasswordHasher<JuiceShopUser> passwordHasher, 
                             IEnumerable<IUserValidator<JuiceShopUser>> userValidators, 
                             IEnumerable<IPasswordValidator<JuiceShopUser>> passwordValidators, 
                             ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, 
                             IServiceProvider services, 
                             ILogger<UserManager<JuiceShopUser>> logger) 
        : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
    {
    }

    [return: NotNullIfNotNull("name")]
    public override string? NormalizeName(string? name)
    {
        return name;
    }
}
