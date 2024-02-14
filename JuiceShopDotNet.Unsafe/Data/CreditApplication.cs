using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace JuiceShopDotNet.Unsafe.Data;

public class CreditApplication
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int CreditApplicationID { get; set; }
    public string UserID { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public DateTime Birthdate { get; set; }
    public string SocialSecurityNumber { get; set; }
    public string EmploymentStatus { get; set; }
    public string Employer { get; set; }
    public float Income { get; set; }
    public bool? IsApproved { get; set; }
    public string? Approver { get; set; }
}
