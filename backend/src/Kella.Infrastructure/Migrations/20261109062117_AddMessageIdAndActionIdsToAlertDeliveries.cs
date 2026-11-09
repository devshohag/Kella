using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Kella.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddMessageIdAndActionIdsToAlertDeliveries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<List<Guid>>(
                name: "ActionIds",
                table: "alert_deliveries",
                type: "uuid[]",
                nullable: false);

            migrationBuilder.AddColumn<long>(
                name: "MessageId",
                table: "alert_deliveries",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Severity",
                table: "alert_deliveries",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ActionIds",
                table: "alert_deliveries");

            migrationBuilder.DropColumn(
                name: "MessageId",
                table: "alert_deliveries");

            migrationBuilder.DropColumn(
                name: "Severity",
                table: "alert_deliveries");
        }
    }
}
