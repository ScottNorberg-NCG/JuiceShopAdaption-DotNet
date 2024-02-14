using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JuiceShopDotNet.Safe.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public virtual DbSet<CreditApplication> CreditApplications { get; set; }
        public virtual DbSet<Order> Orders { get; set; }
        public virtual DbSet<OrderProduct> OrderProducts { get; set; }
        public virtual DbSet<Product> Products { get; set; }
        public virtual DbSet<ProductReview> ProductReviews { get; set; }
        public virtual DbSet<ProductReview_Display> ProductReview_Displays { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<CreditApplication>(entity =>
            {
                entity.ToTable("CreditApplication");

                entity.HasKey("CreditApplicationID");
                entity.Property(e => e.UserID).HasMaxLength(450);
                entity.Property(e => e.FirstName).HasMaxLength(50);
                entity.Property(e => e.LastName).HasMaxLength(50);
                entity.Property(e => e.Birthdate).HasColumnType("datetime");
                entity.Property(e => e.SocialSecurityNumber).HasMaxLength(9);
                entity.Property(e => e.EmploymentStatus).HasMaxLength(15);
                entity.Property(e => e.Employer).HasMaxLength(100);
                entity.Property(e => e.Approver).HasMaxLength(450);
            });

            modelBuilder.Entity<Order>(entity =>
            {
                entity.ToTable("Orders");

                entity.HasKey("OrderID");
                entity.Property(e => e.UserID).HasMaxLength(450);
                entity.Property(e => e.BillingPostalCode).HasMaxLength(25);
                entity.Property(e => e.CreditCardNumber).HasMaxLength(16);
                entity.Property(e => e.CardExpirationMonth).HasMaxLength(2);
                entity.Property(e => e.CardExpirationYear).HasMaxLength(2);
                entity.Property(e => e.CardCvcNumber).HasMaxLength(3);
                entity.Property(e => e.PaymentID).HasMaxLength(200);

                entity.HasMany(e => e.OrderProducts).WithOne(e => e.Order).HasForeignKey(e => e.OrderID);
            });

            modelBuilder.Entity<OrderProduct>(entity =>
            {
                entity.ToTable("OrderProduct");

                entity.HasKey("OrderProductID");
            });

            modelBuilder.Entity<Product>(entity =>
            {
                entity.ToTable("Products");

                entity.HasKey("id");

                entity.HasMany(e => e.ProductReviews).WithOne(e => e.Product).HasForeignKey(e => e.ProductID);
            });

            modelBuilder.Entity<ProductReview>(entity =>
            {
                entity.ToTable("ProductReviews");

                entity.HasKey("ProductReviewID");
                entity.Property(e => e.UserID).HasMaxLength(450);
            });

            modelBuilder.Entity<ProductReview_Display>(entity =>
            {
                entity.ToView("ProductReview_Display").HasNoKey();
            });

            base.OnModelCreating(modelBuilder);
        }
    }
}
