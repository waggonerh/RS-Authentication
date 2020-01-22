using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.ReportingServices.Interfaces;
using System.Linq;
using RSWebAuthentication.SecurityRoles;

namespace RSWebAuthentication
{
    /// <summary>
    /// Implements RS IAuthorizationExtension
    /// Permissions are determined from role claims in the authorization token received from AAD
    /// </summary>
    class TokenAuthorization : IAuthorizationExtension
    {
        static TokenAuthorization()
        {
            InitializeMaps();
        }

        public string LocalizedName
        {
            get
            {
                return null;
            }
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, CatalogOperation requiredOperation)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            //Check Server Roles
            foreach (ISecurityRole role in userServerRoles)
            {
                if (role.CatalogOperations.Contains(requiredOperation))
                {
                    return true;
                }
            }

            //Check ACL Permissions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if(userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (CatalogOperation aclOperation in ace.CatalogOperations)
                    {
                        if (aclOperation == requiredOperation)
                            return true;
                    }
                }
            }

            return false;
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, CatalogOperation[] requiredOperations)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            List<CatalogOperation> aggregateUserPermssions = new List<CatalogOperation>();

            //Aggregate Server Role Permssions
            foreach (ISecurityRole role in userServerRoles)
            {
                aggregateUserPermssions.AddRange(role.CatalogOperations);
            }

            //Aggregate ACL Role Permssions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (CatalogOperation aclOperation in ace.CatalogOperations)
                    {
                        aggregateUserPermssions.Add(aclOperation);
                    }
                }
            }

            return !requiredOperations.Except(aggregateUserPermssions).Any();
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, ReportOperation requiredOperation)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            //Check Server Roles
            foreach (ISecurityRole role in userServerRoles)
            {
                if (role.ReportOperations.Contains(requiredOperation))
                {
                    return true;
                }
            }

            //Check ACL Permissions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (ReportOperation aclOperation in ace.ReportOperations)
                    {
                        if (aclOperation == requiredOperation)
                            return true;
                    }
                }
            }

            return false;
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, FolderOperation requiredOperation)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            //Check Server Roles
            foreach (ISecurityRole role in userServerRoles)
            {
                if (role.FolderOperations.Contains(requiredOperation))
                {
                    return true;
                }
            }

            //Check ACL Permissions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (FolderOperation aclOperation in ace.FolderOperations)
                    {
                        if (aclOperation == requiredOperation)
                            return true;
                    }
                }
            }

            return false;
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, FolderOperation[] requiredOperations)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            List<FolderOperation> aggregateUserPermssions = new List<FolderOperation>();

            //Aggregate Server Role Permssions
            foreach (ISecurityRole role in userServerRoles)
            {
                aggregateUserPermssions.AddRange(role.FolderOperations);
            }

            //Aggregate ACL Role Permssions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (FolderOperation aclOperation in ace.FolderOperations)
                    {
                        aggregateUserPermssions.Add(aclOperation);
                    }
                }
            }

            return !requiredOperations.Except(aggregateUserPermssions).Any();
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, ResourceOperation requiredOperation)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            //Check Server Roles
            foreach (ISecurityRole role in userServerRoles)
            {
                if (role.ResourceOperations.Contains(requiredOperation))
                {
                    return true;
                }
            }

            //Check ACL Permissions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (ResourceOperation aclOperation in ace.ResourceOperations)
                    {
                        if (aclOperation == requiredOperation)
                            return true;
                    }
                }
            }

            return false;
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, ResourceOperation[] requiredOperations)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            List<ResourceOperation> aggregateUserPermssions = new List<ResourceOperation>();

            //Aggregate Server Role Permssions
            foreach (ISecurityRole role in userServerRoles)
            {
                aggregateUserPermssions.AddRange(role.ResourceOperations);
            }

            //Aggregate ACL Role Permssions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (ResourceOperation aclOperation in ace.ResourceOperations)
                    {
                        aggregateUserPermssions.Add(aclOperation);
                    }
                }
            }

            return !requiredOperations.Except(aggregateUserPermssions).Any();
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, DatasourceOperation requiredOperation)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            //Check Server Roles
            foreach (ISecurityRole role in userServerRoles)
            {
                if (role.DatasourceOperations.Contains(requiredOperation))
                {
                    return true;
                }
            }

            //Check ACL Permissions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (DatasourceOperation aclOperation in ace.DatasourceOperations)
                    {
                        if (aclOperation == requiredOperation)
                            return true;
                    }
                }
            }

            return false;
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, ModelOperation requiredOperation)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            //Check Server Roles
            foreach (ISecurityRole role in userServerRoles)
            {
                if (role.ModelOperations.Contains(requiredOperation))
                {
                    return true;
                }
            }

            //Check ACL Permissions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (ModelOperation aclOperation in ace.ModelOperations)
                    {
                        if (aclOperation == requiredOperation)
                            return true;
                    }
                }
            }

            return false;
        }

        public bool CheckAccess(string userName, IntPtr userToken, byte[] secDesc, ModelItemOperation requiredOperation)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            //Check Server Roles
            foreach (ISecurityRole role in userServerRoles)
            {
                if (role.modelItemOperations.Contains(requiredOperation))
                {
                    return true;
                }
            }

            //Check ACL Permissions
            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (ModelItemOperation aclOperation in ace.ModelItemOperations)
                    {
                        if (aclOperation == requiredOperation)
                            return true;
                    }
                }
            }

            return false;
        }

        public byte[] CreateSecurityDescriptor(AceCollection acl, SecurityItemType itemType, out string stringSecDesc)
        {
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            MemoryStream result = new MemoryStream();

            binaryFormatter.Serialize(result, acl);
            stringSecDesc = null;
            return result.GetBuffer();
        }

        public StringCollection GetPermissions(string userName, IntPtr userToken, SecurityItemType itemType, byte[] secDesc)
        {
            ISecurityRole[] userServerRoles = TokenUtilities.GetServerSecurityRolesFromToken(userName);
            string[] userSecurityRoles = TokenUtilities.GetAllSecurityRolesFromToken(userName);

            StringCollection permissions = new StringCollection();

            foreach (ISecurityRole role in userServerRoles)
            {
                foreach (CatalogOperation aclOperation in role.CatalogOperations)
                {
                    if (!permissions.Contains((string)_catalogOperationNames[aclOperation]))
                        permissions.Add((string)_catalogOperationNames[aclOperation]);
                }
                foreach (ReportOperation aclOperation in role.ReportOperations)
                {
                    if (!permissions.Contains((string)_reportOperationNames[aclOperation]))
                        permissions.Add((string)_reportOperationNames[aclOperation]);
                }
                foreach (FolderOperation aclOperation in role.FolderOperations)
                {
                    if (!permissions.Contains((string)_folderOperationNames[aclOperation]))
                        permissions.Add((string)_folderOperationNames[aclOperation]);
                }
                foreach (ResourceOperation aclOperation in role.ResourceOperations)
                {
                    if (!permissions.Contains((string)_resourceOperationNames[aclOperation]))
                        permissions.Add((string)_resourceOperationNames[aclOperation]);
                }
                foreach (DatasourceOperation aclOperation in role.DatasourceOperations)
                {
                    if (!permissions.Contains((string)_datasetOperationNames[aclOperation]))
                        permissions.Add((string)_datasetOperationNames[aclOperation]);
                }
                foreach (ModelOperation aclOperation in role.ModelOperations)
                {
                    if (!permissions.Contains((string)_modelOperationNames[aclOperation]))
                        permissions.Add((string)_modelOperationNames[aclOperation]);
                }
                foreach (ModelItemOperation aclOperation in role.modelItemOperations)
                {
                    if (!permissions.Contains((string)_modelItemOperationNames[aclOperation]))
                        permissions.Add((string)_modelItemOperationNames[aclOperation]);
                }
            }

            AceCollection acl = DeserializeAcl(secDesc);
            foreach (AceStruct ace in acl)
            {
                if (userSecurityRoles.Contains(ace.PrincipalName))
                {
                    foreach (CatalogOperation aclOperation in ace.CatalogOperations)
                    {
                        if (!permissions.Contains((string)_catalogOperationNames[aclOperation]))
                            permissions.Add((string)_catalogOperationNames[aclOperation]);
                    }
                    foreach (ReportOperation aclOperation in ace.ReportOperations)
                    {
                        if (!permissions.Contains((string)_reportOperationNames[aclOperation]))
                            permissions.Add((string)_reportOperationNames[aclOperation]);
                    }
                    foreach (FolderOperation aclOperation in ace.FolderOperations)
                    {
                        if (!permissions.Contains((string)_folderOperationNames[aclOperation]))
                            permissions.Add((string)_folderOperationNames[aclOperation]);
                    }
                    foreach (ResourceOperation aclOperation in ace.ResourceOperations)
                    {
                        if (!permissions.Contains((string)_resourceOperationNames[aclOperation]))
                            permissions.Add((string)_resourceOperationNames[aclOperation]);
                    }
                    foreach (DatasourceOperation aclOperation in ace.DatasourceOperations)
                    {
                        if (!permissions.Contains((string)_datasetOperationNames[aclOperation]))
                            permissions.Add((string)_datasetOperationNames[aclOperation]);
                    }
                    foreach (ModelOperation aclOperation in ace.ModelOperations)
                    {
                        if (!permissions.Contains((string)_modelOperationNames[aclOperation]))
                            permissions.Add((string)_modelOperationNames[aclOperation]);
                    }
                    foreach (ModelItemOperation aclOperation in ace.ModelItemOperations)
                    {
                        if (!permissions.Contains((string)_modelItemOperationNames[aclOperation]))
                            permissions.Add((string)_modelItemOperationNames[aclOperation]);
                    }
                }
            }
            return permissions;
        }
                    
        public void SetConfiguration(string configuration)
        {
            //Read xml from security/configuration section of RSReportServer.config
        }

        private static Dictionary<CatalogOperation, string> _catalogOperationNames = new Dictionary<CatalogOperation, string>();
        private static Dictionary<FolderOperation, string> _folderOperationNames = new Dictionary<FolderOperation, string>();
        private static Dictionary<ReportOperation, string> _reportOperationNames = new Dictionary<ReportOperation, string>();
        private static Dictionary<ResourceOperation, string> _resourceOperationNames = new Dictionary<ResourceOperation, string>();
        private static Dictionary<DatasourceOperation, string> _datasetOperationNames = new Dictionary<DatasourceOperation, string>();
        private static Dictionary<ModelOperation, string> _modelOperationNames = new Dictionary<ModelOperation, string>();
        private static Dictionary<ModelItemOperation, string> _modelItemOperationNames = new Dictionary<ModelItemOperation, string>();
        private static void InitializeMaps()
        {
            _catalogOperationNames.Add(CatalogOperation.CreateRoles, OperationNames.OperCreateRoles);
            _catalogOperationNames.Add(CatalogOperation.DeleteRoles, OperationNames.OperDeleteRoles);
            _catalogOperationNames.Add(CatalogOperation.ReadRoleProperties, OperationNames.OperReadRoleProperties);
            _catalogOperationNames.Add(CatalogOperation.UpdateRoleProperties, OperationNames.OperUpdateRoleProperties);
            _catalogOperationNames.Add(CatalogOperation.ReadSystemProperties, OperationNames.OperReadSystemProperties);
            _catalogOperationNames.Add(CatalogOperation.UpdateSystemProperties, OperationNames.OperUpdateSystemProperties);
            _catalogOperationNames.Add(CatalogOperation.GenerateEvents, OperationNames.OperGenerateEvents);
            _catalogOperationNames.Add(CatalogOperation.ReadSystemSecurityPolicy, OperationNames.OperReadSystemSecurityPolicy);
            _catalogOperationNames.Add(CatalogOperation.UpdateSystemSecurityPolicy, OperationNames.OperUpdateSystemSecurityPolicy);
            _catalogOperationNames.Add(CatalogOperation.CreateSchedules, OperationNames.OperCreateSchedules);
            _catalogOperationNames.Add(CatalogOperation.DeleteSchedules, OperationNames.OperDeleteSchedules);
            _catalogOperationNames.Add(CatalogOperation.ReadSchedules, OperationNames.OperReadSchedules);
            _catalogOperationNames.Add(CatalogOperation.UpdateSchedules, OperationNames.OperUpdateSchedules);
            _catalogOperationNames.Add(CatalogOperation.ListJobs, OperationNames.OperListJobs);
            _catalogOperationNames.Add(CatalogOperation.CancelJobs, OperationNames.OperCancelJobs);
            _catalogOperationNames.Add(CatalogOperation.ExecuteReportDefinition, OperationNames.ExecuteReportDefinition);
            if (_catalogOperationNames.Count != Enum.GetNames(typeof(CatalogOperation)).Length)
            {
                throw new Exception("Number of catalog names don't match.");
            }

            _folderOperationNames.Add(FolderOperation.CreateFolder, OperationNames.OperCreateFolder);
            _folderOperationNames.Add(FolderOperation.Delete, OperationNames.OperDelete);
            _folderOperationNames.Add(FolderOperation.ReadProperties, OperationNames.OperReadProperties);
            _folderOperationNames.Add(FolderOperation.UpdateProperties, OperationNames.OperUpdateProperties);
            _folderOperationNames.Add(FolderOperation.CreateReport, OperationNames.OperCreateReport);
            _folderOperationNames.Add(FolderOperation.CreateResource, OperationNames.OperCreateResource);
            _folderOperationNames.Add(FolderOperation.ReadAuthorizationPolicy, OperationNames.OperReadAuthorizationPolicy);
            _folderOperationNames.Add(FolderOperation.UpdateDeleteAuthorizationPolicy, OperationNames.OperUpdateDeleteAuthorizationPolicy);
            _folderOperationNames.Add(FolderOperation.CreateDatasource, OperationNames.OperCreateDatasource);
            _folderOperationNames.Add(FolderOperation.CreateModel, OperationNames.OperCreateModel);
            if (_folderOperationNames.Count != Enum.GetNames(typeof(FolderOperation)).Length)
            {
                throw new Exception("Number of folder names don't match.");
            }

            _reportOperationNames.Add(ReportOperation.Delete, OperationNames.OperDelete);
            _reportOperationNames.Add(ReportOperation.ReadProperties, OperationNames.OperReadProperties);
            _reportOperationNames.Add(ReportOperation.UpdateProperties, OperationNames.OperUpdateProperties);
            _reportOperationNames.Add(ReportOperation.UpdateParameters, OperationNames.OperUpdateParameters);
            _reportOperationNames.Add(ReportOperation.ReadDatasource, OperationNames.OperReadDatasources);
            _reportOperationNames.Add(ReportOperation.UpdateDatasource, OperationNames.OperUpdateDatasources);
            _reportOperationNames.Add(ReportOperation.ReadReportDefinition, OperationNames.OperReadReportDefinition);
            _reportOperationNames.Add(ReportOperation.UpdateReportDefinition, OperationNames.OperUpdateReportDefinition);
            _reportOperationNames.Add(ReportOperation.CreateSubscription, OperationNames.OperCreateSubscription);
            _reportOperationNames.Add(ReportOperation.DeleteSubscription, OperationNames.OperDeleteSubscription);
            _reportOperationNames.Add(ReportOperation.ReadSubscription, OperationNames.OperReadSubscription);
            _reportOperationNames.Add(ReportOperation.UpdateSubscription, OperationNames.OperUpdateSubscription);
            _reportOperationNames.Add(ReportOperation.CreateAnySubscription, OperationNames.OperCreateAnySubscription);
            _reportOperationNames.Add(ReportOperation.DeleteAnySubscription, OperationNames.OperDeleteAnySubscription);
            _reportOperationNames.Add(ReportOperation.ReadAnySubscription, OperationNames.OperReadAnySubscription);
            _reportOperationNames.Add(ReportOperation.UpdateAnySubscription, OperationNames.OperUpdateAnySubscription);
            _reportOperationNames.Add(ReportOperation.UpdatePolicy, OperationNames.OperUpdatePolicy);
            _reportOperationNames.Add(ReportOperation.ReadPolicy, OperationNames.OperReadPolicy);
            _reportOperationNames.Add(ReportOperation.DeleteHistory, OperationNames.OperDeleteHistory);
            _reportOperationNames.Add(ReportOperation.ListHistory, OperationNames.OperListHistory);
            _reportOperationNames.Add(ReportOperation.ExecuteAndView, OperationNames.OperExecuteAndView);
            _reportOperationNames.Add(ReportOperation.CreateResource, OperationNames.OperCreateResource);
            _reportOperationNames.Add(ReportOperation.CreateSnapshot, OperationNames.OperCreateSnapshot);
            _reportOperationNames.Add(ReportOperation.ReadAuthorizationPolicy, OperationNames.OperReadAuthorizationPolicy);
            _reportOperationNames.Add(ReportOperation.UpdateDeleteAuthorizationPolicy, OperationNames.OperUpdateDeleteAuthorizationPolicy);
            _reportOperationNames.Add(ReportOperation.Execute, OperationNames.OperExecute);
            _reportOperationNames.Add(ReportOperation.CreateLink, OperationNames.OperCreateLink);
            _reportOperationNames.Add(ReportOperation.Comment, OperationNames.OperComment);
            _reportOperationNames.Add(ReportOperation.ManageComments, OperationNames.OperManageComments);
            if (_reportOperationNames.Count != Enum.GetNames(typeof(ReportOperation)).Length)
            {
                throw new Exception("Number of report names don't match.");
            }

            _resourceOperationNames.Add(ResourceOperation.Delete, OperationNames.OperDelete);
            _resourceOperationNames.Add(ResourceOperation.ReadProperties, OperationNames.OperReadProperties);
            _resourceOperationNames.Add(ResourceOperation.UpdateProperties, OperationNames.OperUpdateProperties);
            _resourceOperationNames.Add(ResourceOperation.ReadContent, OperationNames.OperReadContent);
            _resourceOperationNames.Add(ResourceOperation.UpdateContent, OperationNames.OperUpdateContent);
            _resourceOperationNames.Add(ResourceOperation.ReadAuthorizationPolicy, OperationNames.OperReadAuthorizationPolicy);
            _resourceOperationNames.Add(ResourceOperation.UpdateDeleteAuthorizationPolicy, OperationNames.OperUpdateDeleteAuthorizationPolicy);
            _resourceOperationNames.Add(ResourceOperation.Comment, OperationNames.OperComment);
            _resourceOperationNames.Add(ResourceOperation.ManageComments, OperationNames.OperManageComments);
            if (_resourceOperationNames.Count != Enum.GetNames(typeof(ResourceOperation)).Length)
            {
                throw new Exception("Number of resource names don't match.");
            }

            _datasetOperationNames.Add(DatasourceOperation.Delete, OperationNames.OperDelete);
            _datasetOperationNames.Add(DatasourceOperation.ReadProperties, OperationNames.OperReadProperties);
            _datasetOperationNames.Add(DatasourceOperation.UpdateProperties, OperationNames.OperUpdateProperties);
            _datasetOperationNames.Add(DatasourceOperation.ReadContent, OperationNames.OperReadContent);
            _datasetOperationNames.Add(DatasourceOperation.UpdateContent, OperationNames.OperUpdateContent);
            _datasetOperationNames.Add(DatasourceOperation.ReadAuthorizationPolicy, OperationNames.OperReadAuthorizationPolicy);
            _datasetOperationNames.Add(DatasourceOperation.UpdateDeleteAuthorizationPolicy, OperationNames.OperUpdateDeleteAuthorizationPolicy);
            if (_datasetOperationNames.Count != Enum.GetNames(typeof(DatasourceOperation)).Length)
            {
                throw new Exception("Number of datasource names don't match.");
            }

            _modelOperationNames.Add(ModelOperation.Delete, OperationNames.OperDelete);
            _modelOperationNames.Add(ModelOperation.ReadAuthorizationPolicy, OperationNames.OperReadAuthorizationPolicy);
            _modelOperationNames.Add(ModelOperation.ReadContent, OperationNames.OperReadContent);
            _modelOperationNames.Add(ModelOperation.ReadDatasource, OperationNames.OperReadDatasources);
            _modelOperationNames.Add(ModelOperation.ReadModelItemAuthorizationPolicies, OperationNames.OperReadModelItemSecurityPolicies);
            _modelOperationNames.Add(ModelOperation.ReadProperties, OperationNames.OperReadProperties);
            _modelOperationNames.Add(ModelOperation.UpdateContent, OperationNames.OperUpdateContent);
            _modelOperationNames.Add(ModelOperation.UpdateDatasource, OperationNames.OperUpdateDatasources);
            _modelOperationNames.Add(ModelOperation.UpdateDeleteAuthorizationPolicy, OperationNames.OperUpdateDeleteAuthorizationPolicy);
            _modelOperationNames.Add(ModelOperation.UpdateModelItemAuthorizationPolicies, OperationNames.OperUpdateModelItemSecurityPolicies);
            _modelOperationNames.Add(ModelOperation.UpdateProperties, OperationNames.OperUpdatePolicy);
            if (_modelOperationNames.Count != Enum.GetNames(typeof(ModelOperation)).Length)
            {
                throw new Exception("Number of model names don't match.");
            }

            _modelItemOperationNames.Add(ModelItemOperation.ReadProperties, OperationNames.OperReadProperties);
            if (_modelItemOperationNames.Count != Enum.GetNames(typeof(ModelItemOperation)).Length)
            {
                throw new Exception("Number of model item names don't match.");
            }
        }
        private AceCollection DeserializeAcl(byte[] secDesc)
        {
            AceCollection acl = new AceCollection();
            if (secDesc != null)
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();
                using (MemoryStream memoryStream = new MemoryStream(secDesc))
                {
                    acl = (AceCollection)binaryFormatter.Deserialize(memoryStream);
                }
            }
            return acl;
        }
    }
}
