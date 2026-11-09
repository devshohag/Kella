using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Kella.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddIpReputationTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ip_reputation",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServerId = table.Column<Guid>(type: "uuid", nullable: false),
                    Ip = table.Column<string>(type: "text", nullable: false),
                    Listed = table.Column<bool>(type: "boolean", nullable: false),
                    ReturnCode = table.Column<string>(type: "text", nullable: true),
                    ListedSince = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastChecked = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ip_reputation", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ip_reputation_OrganizationId_Ip",
                table: "ip_reputation",
                columns: new[] { "OrganizationId", "Ip" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ip_reputation");
        }
    }
}
