using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Principal;
using System.Web;
using Microsoft.ReportingServices.Interfaces;
using System.Globalization;
using System.Xml;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Collections.Generic;
using Microsoft.Graph;
using System.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Configuration;
using System.Linq;

namespace RSWebAuthentication
{
    /// <summary>
    /// Implements RS IAuthenticationExtension2
    /// </summary>
    public class AuthenticationExtension : IAuthenticationExtension2, IExtension
    {
        private List<AllowedSecurityTypes> _allowedSecurityTypes = new List<AllowedSecurityTypes>();

        private const string _graphRoleFilter = "appId eq '{0}'";
        private const string _graphUserFilter = "userPrincipalName eq '{0}'";
        private const string _graphGroupFilter = "displayName eq '{0}'";

        public string LocalizedName
        {
            get
            {
                return null;
            }
        }

        public void GetUserInfo(out IIdentity userIdentity, out IntPtr userId)
        {
            if (HttpContext.Current != null && HttpContext.Current.User != null)
            {
                userIdentity = HttpContext.Current.User.Identity;
            }
            else
            {
                userIdentity = null; ;
            }

            userId = IntPtr.Zero;
        }

        public void GetUserInfo(IRSRequestContext requestContext, out IIdentity userIdentity, out IntPtr userId)
        {

            if (requestContext != null && requestContext.User != null)
            {
                userIdentity = requestContext.User;
            }
            else
            {
                userIdentity = null;
            }

            userId = IntPtr.Zero;
        }

        public bool IsValidPrincipalName(string principalName)
        {
            JwtSecurityToken token = TokenUtilities.GetTokenFromClientCredentials("https://graph.microsoft.com/");

            GraphServiceClient client = new GraphServiceClient("https://graph.microsoft.com/v1.0",
                new DelegateAuthenticationProvider(
                    async (requestMessage) =>
                    {
                        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("bearer", token.RawData);
                    }));


            foreach (AllowedSecurityTypes securityType in _allowedSecurityTypes)
            {
                if (securityType == AllowedSecurityTypes.Roles)
                {
                    IGraphServiceApplicationsCollectionPage apps =
                        client.Applications.Request().Filter(string.Format(_graphRoleFilter, ConfigurationManager.AppSettings["ClientID"])).Select("appRoles").GetAsync().Result;

                    IEnumerable<string> appRoleValues = apps.CurrentPage[0].AppRoles.Select(t => t.Value);

                    if (appRoleValues.Contains(principalName, StringComparer.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                if (securityType == AllowedSecurityTypes.Users)
                {
                    IGraphServiceUsersCollectionPage users =
                        client.Users.Request().Filter(string.Format(_graphUserFilter, principalName)).Select("userPrincipalName").GetAsync().Result;

                    if (users.CurrentPage.Count == 1 && users.CurrentPage[0].UserPrincipalName.Equals(principalName, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                if (securityType == AllowedSecurityTypes.Groups)
                {
                    IGraphServiceGroupsCollectionPage groups =
                        client.Groups.Request().Filter(string.Format(_graphGroupFilter, principalName)).Select("displayName").GetAsync().Result;

                    if (groups.CurrentPage.Count == 1 && groups.CurrentPage[0].DisplayName.Equals(principalName, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Called when authenticating to the API (non-interactive redirect). Uses the resource owner grant flow to obtain a token.
        /// </summary>
        public bool LogonUser(string userName, string password, string authority)
        {
            AuthenticationResult authResult = null;

            if (!string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(password))
            {
                authResult = TokenUtilities.GetAuthenticationResultFromUserCredentials(userName, password, ConfigurationManager.AppSettings["ClientId"]);
                authResult = TokenUtilities.GetAuthenticationResultFromUserCredentials(userName, password, TokenUtilities.GraphResourceId);
            }

            return authResult != null;
        }

        public void SetConfiguration(string configuration)
        {
            if (!string.IsNullOrEmpty(configuration))
            {
                configuration = String.Concat("<Configuration>", configuration, "</Configuration>");

                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(configuration);
                XmlNode root = xmlDocument.DocumentElement;

                XmlNode xmlSecurityTypes = root.SelectSingleNode("AllowedSecurityTypes");

                foreach (XmlNode child in xmlSecurityTypes.ChildNodes)
                {
                    AllowedSecurityTypes securityType;
                    if (Enum.TryParse(child.Name, out securityType))
                    {
                        _allowedSecurityTypes.Add(securityType);
                    }
                }
            }
        }
    }
}