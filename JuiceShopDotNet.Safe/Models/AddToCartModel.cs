using JuiceShopDotNet.Safe.Data;

namespace JuiceShopDotNet.Safe.Models;

public class AddToCartModel
{
    public Product Product { get; set; }
    public ShoppingCartItem ShoppingCartItem { get; set; }
}
