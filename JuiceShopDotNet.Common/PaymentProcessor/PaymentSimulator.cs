namespace JuiceShopDotNet.Common.PaymentProcessor;

public class PaymentSimulator
{
    public static PaymentResult Pay(PaymentInfo info)
    {
        return new PaymentResult() { PaymentID = Guid.NewGuid(), Result = PaymentResult.ActualResult.Succeeded };
    }
}
