﻿using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace JuiceShopDotNet.Unsafe.Data;

public class OrderProduct
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int OrderProductID { get; set; }
    public int OrderID { get; set; }
    public int ProductID { get; set; }
    public float ProductPrice { get; set; }
    public int Quantity { get; set; }

    public Order Order { get; set; }
}
