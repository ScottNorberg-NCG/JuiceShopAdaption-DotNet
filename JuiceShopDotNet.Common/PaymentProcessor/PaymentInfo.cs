namespace JuiceShopDotNet.Common.PaymentProcessor;

public class PaymentInfo
{
    public string BillingPostalCode { get; set; }
    public string CreditCardNumber { get; set; }
    public string CardExpirationMonth { get; set; }
    public string CardExpirationYear { get; set; }
    public string CardCvcNumber { get; set; }
    public double AmountToCharge { get; set; }
}
