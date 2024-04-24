namespace JuiceShopDotNet.Common.PaymentProcessor;

public class PaymentResult
{
    public enum ActualResult
    { 
        Succeeded,
        Failed
    }

    public Guid? PaymentID { get; set; }
    public List<string> Errors { get; set; } = [];
    public ActualResult Result { get; set; }
}
