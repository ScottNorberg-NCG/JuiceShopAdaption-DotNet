using JuiceShopDotNet.Common.PaymentProcessor;
using JuiceShopDotNet.Safe.Auth;
using JuiceShopDotNet.Safe.Data;
using JuiceShopDotNet.Safe.Data.Extensions;
using JuiceShopDotNet.Safe.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JuiceShopDotNet.Safe.Controllers;

[Authorize]
public class ShoppingController : Controller
{
    private readonly ApplicationDbContext _dbContext;

    public ShoppingController(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public IActionResult Index()
    {
        throw new NotImplementedException();
    }

    [ValidateAntiForgeryToken]
    [HttpPost]
    public IActionResult AddToCart([FromForm]AddToCartModel item)
    {
        if (!ModelState.IsValid)
            return RedirectToAction("Error", "Home");

        var userOrder = _dbContext.Orders.GetOpenOrder(User, false);

        var existingCartItem = userOrder.OrderProducts.SingleOrDefault(i => i.ProductID == item.ProductID);

        if (existingCartItem == null)
        {
            existingCartItem = new OrderProduct();
            existingCartItem.ProductID = item.ProductID;
            userOrder.OrderProducts.Add(existingCartItem);
        }
        else
        {
            var newQuantity = existingCartItem.Quantity + item.Quantity;
            existingCartItem.Quantity = newQuantity;
        }

        var product = _dbContext.Products.SingleOrDefault(p => p.id == item.ProductID);

        //Ensure that the price for these items is the price that was valid at the time of order
        //Note that in a "real" e-commerce system, we would notify the user if the price had changed
        existingCartItem.ProductPrice = product.displayPrice;
        existingCartItem.Quantity = existingCartItem.Quantity + item.Quantity;
        _dbContext.SaveChanges();

        var model = new AddToCartDisplayModel();
        model.OrderProduct = existingCartItem;
        model.Product = product;

        //It's not a good idea to get into the habit of returning EF objects directly to the UI
        //If the schema is exposed, it may give attackers information to better pull off overposting attacks
        //In our case, though, we're just returning the item to the view so no information is exposed
        return View(model);
    }

    [HttpGet]
    public IActionResult Review()
    {
        var userOrder = _dbContext.Orders.GetOpenOrder(User, true);
        return View(userOrder);
    }

    [HttpPost]
    public IActionResult Review(ShoppingCartReviewModel model)
    {
        var userOrder = _dbContext.Orders.GetOpenOrder(User, true);

        if (!ModelState.IsValid)
        {
            return View(userOrder);
        }

        foreach (var key in model.Quantity.Keys)
        {
            var orderProduct = userOrder.OrderProducts.SingleOrDefault(op => op.ProductID == key);

            if (orderProduct == null)
            {
                ModelState.AddModelError("Product Not Found", "There was an error during the review process. Please try again.");
                return View(userOrder);
            }

            orderProduct.Quantity = model.Quantity[key];
        }

        _dbContext.SaveChanges();

        return RedirectToAction(nameof(Checkout));
    }

    [HttpGet]
    public IActionResult Checkout()
    {
        return View(new CheckoutModel());
    }

    [HttpPost]
    public IActionResult Checkout(CheckoutModel model)
    {
        var order = _dbContext.Orders.GetOpenOrder(User, false);
        var amount = order.OrderProducts.Sum(op => op.ProductPrice * op.Quantity);

        var paymentInfo = new PaymentInfo()
        {
            BillingPostalCode = model.BillingPostalCode,
            CreditCardNumber = model.CreditCardNumber,
            CardExpirationMonth = model.CardExpirationMonth,
            CardExpirationYear = model.CardExpirationYear.ToString(),
            CardCvcNumber = model.CardCvcNumber,
            AmountToCharge = amount
        };

        var result = PaymentSimulator.Pay(paymentInfo);

        if (result.Result == PaymentResult.ActualResult.Succeeded)
        {
            order.PaymentID = result.PaymentID.Value.ToString();
            order.AmountPaid = amount;
            order.OrderCompletedOn = DateTime.Now;

            _dbContext.SaveChanges();

            return RedirectToAction(nameof(Completed));
        }
        else
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(error, "");
            }

            return View(model);
        }
    }

    [HttpGet]
    public IActionResult Completed()
    {
        return View();
    }
}
