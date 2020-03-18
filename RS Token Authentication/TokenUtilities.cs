using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Configuration;
using System.Web;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Collections.Generic;

namespace RSWebAuthentication
{
    internal enum AllowedSecurityTypes
    {
        Users,
        Roles
    }

    /// <summary>
    /// Helper class to handle token requests from AAD and retrieve role claims.
    /// </summary>
    internal class TokenUtilities
    {
        internal static readonly string GraphResourceId = "00000003-0000-0000-c000-000000000000";

        internal static AuthenticationResult GetAuthenticationResultFromAuthCode(string code)
        {
            string redirectUri = ConfigurationManager.AppSettings["RedirectURI"];

            AuthenticationContext authContext = new AuthenticationContext(ConfigurationManager.AppSettings["AuthorityURI"], new ADALTokenCache());
            ClientCredential clientCredential = new ClientCredential(
                ConfigurationManager.AppSettings["ClientID"],
                ConfigurationManager.AppSettings["ClientSecret"]);

            return authContext.AcquireTokenByAuthorizationCode(code, new Uri(ConfigurationManager.AppSettings["RedirectURI"]), clientCredential);
        }

        internal static AuthenticationResult GetAuthenticationResultFromUserCredentials(string userName, string password, string resource)
        {
            string authority = ConfigurationManager.AppSettings["AuthorityURI"];
            AuthenticationContext authContext = new AuthenticationContext(authority, new ADALTokenCache());

            UserCredential userCredential = new UserCredential(userName, password);
            string clientId = ConfigurationManager.AppSettings["APIClientId"];

            AuthenticationResult authResult = authContext.AcquireToken(resource, clientId, userCredential);

            return authResult;
        }
        internal static JwtSecurityToken GetTokenFromClientCredentials(string resource)
        {
            AuthenticationContext authContext = new AuthenticationContext(ConfigurationManager.AppSettings["AuthorityURI"]);

            ClientCredential clientCredential = new ClientCredential(
                ConfigurationManager.AppSettings["ClientID"],
                ConfigurationManager.AppSettings["ClientSecret"]);


            AuthenticationResult authResult = authContext.AcquireToken(resource, clientCredential);

            return new JwtSecurityToken(authResult.AccessToken);
        }

        internal static JwtSecurityToken GetCachedIdToken(string userName)
        {
            AuthenticationContext authContext = new AuthenticationContext(ConfigurationManager.AppSettings["AuthorityURI"], new ADALTokenCache());
            UserIdentifier userId = new UserIdentifier(userName, UserIdentifierType.RequiredDisplayableId);
            AuthenticationResult authResult;
            string resource;
            JwtSecurityToken jwtToken;

            if (IsInteractiveAuth())
            {
                ClientCredential clientCredential = new ClientCredential(
                    ConfigurationManager.AppSettings["ClientID"],
                    ConfigurationManager.AppSettings["ClientSecret"]);

                resource = TokenUtilities.GraphResourceId;
                authResult = authContext.AcquireTokenSilent(resource, clientCredential, userId);
            }
            else
            {
                string clientId = ConfigurationManager.AppSettings["APIClientId"];
                resource = ConfigurationManager.AppSettings["ClientId"];

                authResult = authContext.AcquireTokenSilent(resource, clientId, userId);
            }

            jwtToken = new JwtSecurityToken(authResult.IdToken);
            return jwtToken;
        }

        internal static string[] GetAllClaimsFromToken(string userName, string claimType)
        {
            JwtSecurityToken jwtToken = GetCachedIdToken(userName);
            return jwtToken.Claims.Where(claim => claim.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase)).Select(claim => claim.Value).ToArray();
        }

        internal static string[] GetRolesForUserFromGraph(string userName)
        {
            List<Graph.AppRoleAssignment> appRoleAssignments = Graph.AppRoleAssignment.GetAssignedRolesForUser(userName, ConfigurationManager.AppSettings["EnterpriseAppId"]);
            List<Graph.AppRole> appRoles = Graph.AppRole.GetRolesForApplication(ConfigurationManager.AppSettings["ClientID"]);

            var userRoles = appRoleAssignments
                .Join(appRoles,
                assignments => assignments.AppRoleId,
                roles => roles.Id,
                (assignments, roles) => new { AppRoleAssignment = assignments, AppRoles = roles });

            return userRoles.Select(t => t.AppRoles.Value).Distinct().ToArray();
        }

        private static bool IsInteractiveAuth()
        {
            if (HttpContext.Current != null)
            {
                var isInteractiveAuth = HttpContext.Current.Request.Cookies["RSTypeAuthCookie"]?.Values["IsInteractiveAuth"] ?? "false";
                return bool.Parse(isInteractiveAuth);
            }
            else
            {
                return true;
            }
        }
    }
}