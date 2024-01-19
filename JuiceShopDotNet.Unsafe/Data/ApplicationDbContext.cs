using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JuiceShopDotNet.Unsafe.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public virtual DbSet<Product> Products { get; set; }

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
            });

            base.OnModelCreating(modelBuilder);
        }
    }
}
