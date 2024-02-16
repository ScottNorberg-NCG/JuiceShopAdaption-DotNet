using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace JuiceShopDotNet.Safe.Data;

public class CreditApplication
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int CreditApplicationID { get; set; }
    public string UserID { get; set; }
    public string FullName { get; set; }
    public DateTime Birthdate { get; set; }
    public string SocialSecurityNumber { get; set; }
    public string EmploymentStatus { get; set; }
    public DateTime SubmittedOn { get; set; }
    public int Income { get; set; }
    public bool? IsApproved { get; set; }
    public string? Approver { get; set; }
    public DateTime? DecisionDate { get; set; }
}
