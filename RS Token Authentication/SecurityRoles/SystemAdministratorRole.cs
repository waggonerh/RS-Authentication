using Microsoft.ReportingServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RSWebAuthentication.SecurityRoles
{
    internal class SystemAdministratorRole : ISecurityRole
    {
        internal SystemAdministratorRole()
        {
            CatalogOperations = new CatalogOperation[] {
                CatalogOperation.ListJobs,
                CatalogOperation.CancelJobs,
                CatalogOperation.ReadSystemProperties,
                CatalogOperation.UpdateSystemProperties,
                CatalogOperation.ExecuteReportDefinition,
                CatalogOperation.CreateSchedules,
                CatalogOperation.DeleteSchedules,
                CatalogOperation.ReadSchedules,
                CatalogOperation.UpdateSchedules,
                CatalogOperation.ReadSystemSecurityPolicy,
                CatalogOperation.UpdateSystemSecurityPolicy,
                CatalogOperation.CreateRoles,
                CatalogOperation.DeleteRoles,
                CatalogOperation.ReadRoleProperties,
                CatalogOperation.UpdateRoleProperties,
                CatalogOperation.GenerateEvents
            };
            ReportOperations = new ReportOperation[] { };
            FolderOperations = new FolderOperation[] { };
            ResourceOperations = new ResourceOperation[] { };
            DatasourceOperations = new DatasourceOperation[] { };
            ModelOperations = new ModelOperation[] { };
            modelItemOperations = new ModelItemOperation[] { };
        }
        public CatalogOperation[] CatalogOperations { get; }
        public ReportOperation[] ReportOperations { get; }
        public FolderOperation[] FolderOperations { get; }
        public ResourceOperation[] ResourceOperations { get; }
        public DatasourceOperation[] DatasourceOperations { get; }
        public ModelOperation[] ModelOperations { get; }
        public ModelItemOperation[] modelItemOperations { get; }
    }
}