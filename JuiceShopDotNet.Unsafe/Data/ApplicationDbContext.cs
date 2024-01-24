using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JuiceShopDotNet.Unsafe.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        //public virtual DbSet<AspNetUser> AspNetUsers { get; set; }
        public virtual DbSet<Product> Products { get; set; }
        public virtual DbSet<ProductReview> ProductReviews { get; set; }
        public virtual DbSet<ProductReview_Display> ProductReview_Displays { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
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

            //modelBuilder.Entity<AspNetUser>(entity =>
            //{
            //    entity.Property(e => e.Email).HasMaxLength(256);
            //    entity.Property(e => e.NormalizedEmail).HasMaxLength(256);
            //    entity.Property(e => e.NormalizedUserName).HasMaxLength(256);
            //    entity.Property(e => e.UserName).HasMaxLength(256);

            //    entity.HasOne<IdentityUser>().WithOne()
            //        .HasForeignKey<IdentityUser>(e => e.Id);
            //    //entity.HasMany(d => d.Roles).WithMany(p => p.Users)
            //    //    .UsingEntity<Dictionary<string, object>>(
            //    //        "AspNetUserRole",
            //    //        r => r.HasOne<AspNetRole>().WithMany().HasForeignKey("RoleId"),
            //    //        l => l.HasOne<AspNetUser>().WithMany().HasForeignKey("UserId"),
            //    //        j =>
            //    //        {
            //    //            j.HasKey("UserId", "RoleId");
            //    //            j.ToTable("AspNetUserRoles");
            //    //        });
            //});
        }
    }
}
