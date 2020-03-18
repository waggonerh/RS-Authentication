using System;
using System.Data;
using System.Security.Principal;
using System.Web;
using Microsoft.ReportingServices.Interfaces;
using System.Xml;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Collections.Generic;
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
        //private const string _graphGroupFilter = "displayName eq '{0}'";

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
            if (_allowedSecurityTypes.Contains(AllowedSecurityTypes.Roles))
            {
                List<Graph.AppRole> appRoleAssignments = Graph.AppRole.GetRolesForApplication(ConfigurationManager.AppSettings["ClientID"]);

                IEnumerable<string> appRoleValues = appRoleAssignments.Select(t => t.Value);

                if (appRoleValues.Contains(principalName, StringComparer.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            if (_allowedSecurityTypes.Contains(AllowedSecurityTypes.Roles))
            {
                List<Graph.User> users = Graph.User.GetUsers(principalName);

                if (users.Count == 1 && users[0].UserPrincipalName.Equals(principalName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
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
            }

            if (authResult == null)
            {
                return false;
            }
            else
            {
                HttpCookie cookie = new HttpCookie("RSTypeAuthCookie");
                cookie.Values.Add("IsInteractiveAuth", "false");

                HttpContext.Current.Response.Cookies.Set(cookie);
                return true;
            }
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