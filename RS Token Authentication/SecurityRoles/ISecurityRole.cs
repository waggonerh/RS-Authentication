using Microsoft.ReportingServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RSWebAuthentication.SecurityRoles
{
    internal interface ISecurityRole
    {
        CatalogOperation[] CatalogOperations { get; }
        ReportOperation[] ReportOperations { get; }
        FolderOperation[] FolderOperations { get; }
        ResourceOperation[] ResourceOperations { get; }
        DatasourceOperation[] DatasourceOperations { get; }
        ModelOperation[] ModelOperations { get; }
        ModelItemOperation[] modelItemOperations { get; }
    }
}