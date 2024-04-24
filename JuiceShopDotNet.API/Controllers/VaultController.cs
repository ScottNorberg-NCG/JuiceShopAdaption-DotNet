using JuiceShopDotNet.API.Authorization;
using JuiceShopDotNet.API.Data;
using JuiceShopDotNet.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JuiceShopDotNet.API.Controllers;

[Authorize]
[ApiController]
[Route("[controller]/[action]")]
public class VaultController(DatabaseContext databaseContext) : Controller
{
    private readonly DatabaseContext _dbContext = databaseContext;

    [HttpPost]
    [ValidateSignature]
    public IActionResult GetCreditApplication([FromBody]IDWrapper model)
    {
        var application = _dbContext.CreditApplications.Single(ca => ca.CreditApplicationID == model.id);

        var toReturn = new CreditApplicationModel
        {
            CreditApplicationID = application.CreditApplicationID,
            SocialSecurityNumber = application.SocialSecurityNumber
        };

        return Json(toReturn);
    }

    [HttpPost]
    [ValidateSignature]
    public IActionResult SaveCreditApplication([FromBody]CreditApplicationModel model)
    {
        var newApplication = _dbContext.CreditApplications.SingleOrDefault(ca => ca.CreditApplicationID == model.CreditApplicationID);

        if (newApplication == null) 
        {
            newApplication = new CreditApplication
            {
                CreditApplicationID = model.CreditApplicationID
            };
            _dbContext.CreditApplications.Add(newApplication);
        }

        newApplication.SocialSecurityNumber = model.SocialSecurityNumber;
        _dbContext.SaveChanges();

        return Ok();
    }

    [HttpPost]
    [ValidateSignature]
    public IActionResult GetJuiceShopUser([FromBody] IDWrapper model)
    {
        var user = _dbContext.JuiceShopUsers.Single(u => u.JuiceShopUserID == model.id);

        var toReturn = new JuiceShopUserModel
        {
            JuiceShopUserID = user.JuiceShopUserID,
            UserName = user.UserName,
            UserEmail = user.UserEmail,
            NormalizedUserEmail = user.NormalizedUserEmail
        };

        return Json(toReturn);
    }

    [HttpPost]
    [ValidateSignature]
    public IActionResult SaveJuiceShopUser([FromBody] JuiceShopUserModel model)
    {
        JuiceShopUser newUser = EnsureUser(model);

        newUser.UserName = model.UserName;
        newUser.UserEmail = model.UserEmail;
        newUser.NormalizedUserEmail = model.NormalizedUserEmail;
        _dbContext.SaveChanges();

        return Ok();
    }

    private JuiceShopUser EnsureUser(JuiceShopUserModel model)
    {
        var newUser = _dbContext.JuiceShopUsers.SingleOrDefault(u => u.JuiceShopUserID == model.JuiceShopUserID);

        if (newUser == null)
        {
            newUser = new JuiceShopUser
            {
                JuiceShopUserID = model.JuiceShopUserID
            };
            _dbContext.JuiceShopUsers.Add(newUser);
        }

        return newUser;
    }
}
