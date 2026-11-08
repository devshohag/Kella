using Shield.Core;

namespace Shield.Infrastructure;

/// <summary>Scoped holder for the current organization. Set by auth middleware or by workers per event.</summary>
public sealed class OrgContext : IOrgContext
{
    public Guid? OrganizationId { get; private set; }

    public void Set(Guid organizationId)
    {
        if (OrganizationId is not null && OrganizationId != organizationId)
            throw new InvalidOperationException("Organization already set for this scope.");
        OrganizationId = organizationId;
    }
}
