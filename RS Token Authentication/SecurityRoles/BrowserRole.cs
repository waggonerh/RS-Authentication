using Microsoft.ReportingServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RSWebAuthentication.SecurityRoles
{
    internal class BrowserRole : ISecurityRole
    {
        internal BrowserRole()
        {
            CatalogOperations = new CatalogOperation[] { };
            ReportOperations = new ReportOperation[] { 
                ReportOperation.ExecuteAndView,
                ReportOperation.Execute,
                ReportOperation.ReadProperties,
                ReportOperation.CreateSubscription,
                ReportOperation.DeleteSubscription,
                ReportOperation.ReadSubscription,
                ReportOperation.UpdateSubscription
            };
            FolderOperations = new FolderOperation[] {
                FolderOperation.ReadProperties
            };
            ResourceOperations = new ResourceOperation[] {
                ResourceOperation.ReadProperties
            };
            DatasourceOperations = new DatasourceOperation[] { };
            ModelOperations = new ModelOperation[] { 
                ModelOperation.ReadDatasource,
                ModelOperation.ReadProperties
            };
            modelItemOperations = new ModelItemOperation[] {
                ModelItemOperation.ReadProperties
            };
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