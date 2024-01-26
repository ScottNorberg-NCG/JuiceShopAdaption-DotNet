﻿using JuiceShopDotNet.Unsafe.Data;
using JuiceShopDotNet.Unsafe.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JuiceShopDotNet.Unsafe.Controllers;

[AutoValidateAntiforgeryToken]
public class ProductController : Controller
{
    private readonly ApplicationDbContext _dbContext;

    public ProductController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public IActionResult Index(int page, int pageSize)
    {
        if (pageSize <= 0)
            pageSize = 12;

        if (page <= 1)
            page = 1;

        var model = new HomeModel();
        model.Products = _dbContext.Products.OrderBy(p => p.name).Skip((page - 1) * pageSize).Take(pageSize).ToList();
        model.PageNumber = page;
        model.PageSize = pageSize;
        model.TotalProductCount = _dbContext.Products.Count();

        return View(model);
    }

    public IActionResult Details(int id)
    {
        var model = new ProductDetailsModel();
        model.Product = _dbContext.Products.FirstOrDefault(p => p.id == id);
        model.ProductReviews = _dbContext.ProductReview_Displays.Where(p => p.ProductID == id).ToList();
        return View(model);
    }

    public IActionResult AddReview(int id, string reviewText)
    {
        var newReview = new ProductReview();
        newReview.ProductID = id;
        newReview.ReviewText = reviewText;
        newReview.UserID = User.Claims.Single(c => c.Type == ClaimTypes.NameIdentifier).Value;
        _dbContext.ProductReviews.Add(newReview);
        _dbContext.SaveChanges();

        return RedirectToAction("Details", "Product", new { id });
    }
}
