﻿using Microsoft.ReportingServices.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace RSWebAuthentication.SecurityRoles
{
    internal class SystemUserRole : ISecurityRole
    {
        internal SystemUserRole()
        {
            CatalogOperations = new CatalogOperation[] {
                CatalogOperation.ExecuteReportDefinition,
                CatalogOperation.ReadSystemProperties,
                CatalogOperation.ReadSchedules
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