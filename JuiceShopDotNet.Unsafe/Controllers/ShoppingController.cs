using JuiceShopDotNet.Unsafe.Data;
using JuiceShopDotNet.Unsafe.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace JuiceShopDotNet.Unsafe.Controllers
{
    [AutoValidateAntiforgeryToken]
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

        public IActionResult AddToCart(ShoppingCartItem item)
        {
            var cartAsString = Request.Cookies["ShoppingCart"];
            var cart = new List<ShoppingCartItem>();

            if (!string.IsNullOrEmpty(cartAsString))
                cart = System.Text.Json.JsonSerializer.Deserialize<List<ShoppingCartItem>>(cartAsString);

            var existingCartItem = cart.SingleOrDefault(i => i.ProductID == item.ProductID);

            if (existingCartItem == null)
                cart.Add(item);
            else
            {
                var newQuantity = existingCartItem.Quantity + item.Quantity;
                cart.Single(i => i.ProductID == item.ProductID).Quantity = newQuantity;
                item.Quantity = newQuantity;
            }

            var cartItem = cart.Single(i => i.ProductID == item.ProductID);
            var product = _dbContext.Products.SingleOrDefault(p => p.id == item.ProductID);

            cartItem.Price = item.Price;
            cartItem.ProductName = product.name;
            cartItem.ImageName = product.image;

            var cookieOptions = new CookieOptions();
            cookieOptions.SameSite = SameSiteMode.None;
            cookieOptions.HttpOnly = false;
            cookieOptions.Secure = false;

            Response.Cookies.Delete("ShoppingCart");
            Response.Cookies.Append("ShoppingCart", JsonSerializer.Serialize(cart), cookieOptions);

            var model = new AddToCartModel();
            model.ShoppingCartItem = item;
            model.Product = product;

            return View(model);
        }

        public IActionResult Review()
        {
            return View();
        }
    }
}
