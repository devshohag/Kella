using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Kella.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAlertDeliveryChatId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ChatId",
                table: "alert_deliveries",
                type: "text",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_alert_deliveries_OrganizationId_ChatId_MessageId",
                table: "alert_deliveries",
                columns: new[] { "OrganizationId", "ChatId", "MessageId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_alert_deliveries_OrganizationId_ChatId_MessageId",
                table: "alert_deliveries");

            migrationBuilder.DropColumn(
                name: "ChatId",
                table: "alert_deliveries");
        }
    }
}
