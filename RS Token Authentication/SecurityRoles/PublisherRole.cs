using Microsoft.ReportingServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RSWebAuthentication.SecurityRoles
{
    internal class PublisherRole : ISecurityRole
    {
        internal PublisherRole()
        {
            CatalogOperations = new CatalogOperation[] { };
            ReportOperations = new ReportOperation[] {
                ReportOperation.CreateLink,
                ReportOperation.Delete,
                ReportOperation.UpdateParameters,
                ReportOperation.ReadProperties,
                ReportOperation.UpdateProperties,
                ReportOperation.ReadDatasource,
                ReportOperation.UpdateDatasource,
                ReportOperation.ReadReportDefinition,
                ReportOperation.UpdateReportDefinition
            };
            FolderOperations = new FolderOperation[] {
                FolderOperation.CreateDatasource,
                FolderOperation.CreateFolder,
                FolderOperation.CreateModel,
                FolderOperation.CreateReport,
                FolderOperation.CreateResource,
                FolderOperation.Delete,
                FolderOperation.ReadProperties,
                FolderOperation.UpdateProperties
            };
            ResourceOperations = new ResourceOperation[] { 
                ResourceOperation.ReadContent,
                ResourceOperation.UpdateContent,
                ResourceOperation.ReadProperties,
                ResourceOperation.UpdateProperties,
                ResourceOperation.Delete
            };
            DatasourceOperations = new DatasourceOperation[] {
                DatasourceOperation.Delete,
                DatasourceOperation.ReadContent,
                DatasourceOperation.UpdateContent,
                DatasourceOperation.ReadProperties,
                DatasourceOperation.UpdateProperties
            };
            ModelOperations = new ModelOperation[] {
                ModelOperation.ReadContent,
                ModelOperation.UpdateContent,
                ModelOperation.Delete,
                ModelOperation.ReadProperties,
                ModelOperation.UpdateProperties
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