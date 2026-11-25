using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

namespace DotnetApi;

public class Customer
{
    public long Id { get; set; }
    public string Email { get; set; } = "";
    public string FullName { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

public class Order
{
    public long Id { get; set; }
    public long CustomerId { get; set; }
    public decimal Total { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<Order> Orders => Set<Order>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Customer>(e =>
        {
            e.ToTable("customers", "public");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasColumnName("id").UseIdentityByDefaultColumn();
            e.Property(x => x.Email).HasColumnName("email").HasMaxLength(255).IsRequired();
            e.Property(x => x.FullName).HasColumnName("full_name").HasMaxLength(255).IsRequired();
            e.Property(x => x.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz")
                .HasDefaultValueSql("now()").ValueGeneratedOnAdd();
        });

        b.Entity<Order>(e =>
        {
            e.ToTable("orders", "public");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasColumnName("id").UseIdentityByDefaultColumn();
            e.Property(x => x.CustomerId).HasColumnName("customer_id");
            e.Property(x => x.Total).HasColumnName("total").HasColumnType("numeric(10,2)");
            e.Property(x => x.CreatedAt).HasColumnName("created_at").HasColumnType("timestamptz")
                .HasDefaultValueSql("now()").ValueGeneratedOnAdd();
            e.HasOne<Customer>().WithMany().HasForeignKey(x => x.CustomerId);
        });
    }
}

// Hand-written migration (no Designer / snapshot files).
[DbContext(typeof(AppDbContext))]
[Migration("20261116000000_Initial")]
public class Initial : Migration
{
    protected override void Up(MigrationBuilder m)
    {
        m.CreateTable(
            name: "customers",
            schema: "public",
            columns: t => new
            {
                id = t.Column<long>(type: "bigint", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                email = t.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                full_name = t.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                created_at = t.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
            },
            constraints: t => t.PrimaryKey("PK_customers", x => x.id));

        m.CreateTable(
            name: "orders",
            schema: "public",
            columns: t => new
            {
                id = t.Column<long>(type: "bigint", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                customer_id = t.Column<long>(type: "bigint", nullable: false),
                total = t.Column<decimal>(type: "numeric(10,2)", nullable: false),
                created_at = t.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
            },
            constraints: t =>
            {
                t.PrimaryKey("PK_orders", x => x.id);
                t.ForeignKey("FK_orders_customers_customer_id", x => x.customer_id,
                    principalSchema: "public", principalTable: "customers", principalColumn: "id");
            });

        m.CreateIndex("IX_orders_customer_id", "orders", "customer_id", schema: "public");

        // Fake seed data. Ids come from the identity sequence (1..3 on a fresh table).
        m.Sql("""
            INSERT INTO public.customers (email, full_name) VALUES
              ('alice@example.com', 'Alice Example'),
              ('bob@example.com', 'Bob Sample'),
              ('carol@example.com', 'Carol Test');
            INSERT INTO public.orders (customer_id, total)
              SELECT c.id, v.total FROM (VALUES
                ('alice@example.com', 19.99),
                ('alice@example.com', 5.50),
                ('bob@example.com', 120.00),
                ('carol@example.com', 42.42)
              ) AS v(email, total)
              JOIN public.customers c ON c.email = v.email;
            """);
    }

    protected override void Down(MigrationBuilder m)
    {
        m.DropTable("orders", schema: "public");
        m.DropTable("customers", schema: "public");
    }
}
