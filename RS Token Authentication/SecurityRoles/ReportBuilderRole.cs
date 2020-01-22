using Microsoft.ReportingServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RSWebAuthentication.SecurityRoles
{
    internal class ReportBuilderRole : ISecurityRole
    {
        internal ReportBuilderRole()
        {
            CatalogOperations = new CatalogOperation[] { };
            ReportOperations = new ReportOperation[] {
                ReportOperation.ReadReportDefinition,
                ReportOperation.Execute,
                ReportOperation.ExecuteAndView,
                ReportOperation.ReadProperties,
                ReportOperation.CreateSubscription,
                ReportOperation.DeleteSubscription,
                ReportOperation.ReadSubscription,
                ReportOperation.UpdateSubscription
            };
            FolderOperations = new FolderOperation[] { };
            ResourceOperations = new ResourceOperation[] {
                ResourceOperation.ReadContent,
                ResourceOperation.ReadProperties
            };
            DatasourceOperations = new DatasourceOperation[] { };
            ModelOperations = new ModelOperation[] {
                ModelOperation.ReadDatasource
            };
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