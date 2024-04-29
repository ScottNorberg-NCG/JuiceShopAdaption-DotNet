using JuiceShopDotNet.Safe.Data;
using JuiceShopDotNet.Safe.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JuiceShopDotNet.Safe.Controllers;

[Authorize]
public class CreditController(ApplicationDbContext dbContext) : Controller
{
    private readonly ApplicationDbContext _dbContext = dbContext;

    [HttpGet]
    public IActionResult Index()
    {
        var userID = int.Parse(HttpContext.User.Claims.Single(c => c.Type == ClaimTypes.NameIdentifier).Value);
        var creditApplication = _dbContext.CreditApplications.SingleOrDefault(c => c.UserID == userID);
        return View(creditApplication);
    }

    [HttpGet]
    public IActionResult Apply()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Apply([FromForm]CreditApplicationModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var newApp = new CreditApplication
        {
            UserID = int.Parse(HttpContext.User.Claims.Single(c => c.Type == ClaimTypes.NameIdentifier).Value),
            FullName = model.FullName,
            Birthdate = model.Birthdate,
            SocialSecurityNumber = model.SocialSecurityNumber,
            EmploymentStatus = model.EmploymentStatus,
            Income = model.Income,
            SubmittedOn = DateTime.UtcNow
        };

        _dbContext.Add(newApp);
        _dbContext.SaveChanges();

        return RedirectToAction("Index");
    }
}
