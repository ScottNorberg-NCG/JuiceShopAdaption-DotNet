using JuiceShopDotNet.Safe.Data;

namespace JuiceShopDotNet.Safe.Models;

public class ProductDetailsModel
{
    public Product Product { get; set; }
    public List<ProductReview_Display> ProductReviews { get; set; }
}
