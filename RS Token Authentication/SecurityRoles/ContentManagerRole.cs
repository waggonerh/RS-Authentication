using Microsoft.ReportingServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RSWebAuthentication.SecurityRoles
{
    internal class ContentManagerRole : ISecurityRole
    {
        internal ContentManagerRole()
        {
            CatalogOperations = new CatalogOperation[] { };
            ReportOperations = new ReportOperation[] {
                ReportOperation.ReadReportDefinition,
                ReportOperation.CreateLink,
                ReportOperation.CreateAnySubscription,
                ReportOperation.DeleteAnySubscription,
                ReportOperation.ReadAnySubscription,
                ReportOperation.UpdateAnySubscription,
                ReportOperation.ListHistory,
                ReportOperation.DeleteHistory,
                ReportOperation.UpdateReportDefinition,
                ReportOperation.Delete,
                ReportOperation.ReadProperties,
                ReportOperation.UpdateProperties,
                ReportOperation.ReadDatasource,
                ReportOperation.UpdateDatasource,
                ReportOperation.UpdateParameters,
                ReportOperation.Execute,
                ReportOperation.ExecuteAndView,
                ReportOperation.CreateSnapshot,
                ReportOperation.CreateResource,
                ReportOperation.ReadAuthorizationPolicy,
                ReportOperation.UpdateDeleteAuthorizationPolicy
            };
            FolderOperations = new FolderOperation[] {
                FolderOperation.CreateFolder,
                FolderOperation.Delete,
                FolderOperation.ReadProperties,
                FolderOperation.UpdateProperties,
                FolderOperation.CreateModel,
                FolderOperation.CreateReport,
                FolderOperation.CreateResource,
                FolderOperation.CreateDatasource,
                FolderOperation.ReadAuthorizationPolicy,
                FolderOperation.UpdateDeleteAuthorizationPolicy
            };
            ResourceOperations = new ResourceOperation[] {
                ResourceOperation.UpdateContent,
                ResourceOperation.Delete,
                ResourceOperation.ReadContent,
                ResourceOperation.UpdateProperties,
                ResourceOperation.ReadProperties,
                ResourceOperation.ReadAuthorizationPolicy,
                ResourceOperation.UpdateDeleteAuthorizationPolicy
            };
            DatasourceOperations = new DatasourceOperation[] {
                DatasourceOperation.Delete,
                DatasourceOperation.ReadContent,
                DatasourceOperation.ReadProperties,
                DatasourceOperation.UpdateContent,
                DatasourceOperation.UpdateProperties,
                DatasourceOperation.ReadAuthorizationPolicy,
                DatasourceOperation.UpdateDeleteAuthorizationPolicy
            };
            ModelOperations = new ModelOperation[] {
                ModelOperation.ReadContent,
                ModelOperation.UpdateContent,
                ModelOperation.ReadProperties,
                ModelOperation.UpdateProperties,
                ModelOperation.Delete,
                ModelOperation.ReadDatasource,
                ModelOperation.UpdateDatasource,
                ModelOperation.ReadAuthorizationPolicy,
                ModelOperation.ReadModelItemAuthorizationPolicies,
                ModelOperation.UpdateDeleteAuthorizationPolicy,
                ModelOperation.UpdateModelItemAuthorizationPolicies
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