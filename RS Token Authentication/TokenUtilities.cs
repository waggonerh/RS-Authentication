using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Configuration;
using System.Web;
using RSWebAuthentication.SecurityRoles;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;

namespace RSWebAuthentication
{
    /// <summary>
    /// Helper class to handle token requests from AAD and retrieve role claims.
    /// </summary>
    internal class TokenUtilities
    {
        internal static AuthenticationResult GetTokenFromAuthCode(string code)
        {
            string redirectUri = ConfigurationManager.AppSettings["RedirectURI"];

            AuthenticationContext authContext = new AuthenticationContext(ConfigurationManager.AppSettings["AuthorityURI"], new ADALTokenCache());
            ClientCredential clientCredential = new ClientCredential(
                ConfigurationManager.AppSettings["ClientID"],
                ConfigurationManager.AppSettings["ClientSecret"]);

            return authContext.AcquireTokenByAuthorizationCode(code, new Uri(ConfigurationManager.AppSettings["RedirectURI"]), clientCredential);
        }

        internal static AuthenticationResult GetTokenFromCache(string userName)
        {
            AuthenticationContext authContext = new AuthenticationContext(ConfigurationManager.AppSettings["AuthorityURI"], new ADALTokenCache());
            UserIdentifier userId = new UserIdentifier(userName, UserIdentifierType.RequiredDisplayableId);

            if (IsInteractiveAuth())
            {
                ClientCredential clientCredential = new ClientCredential(
                    ConfigurationManager.AppSettings["ClientID"],
                    ConfigurationManager.AppSettings["ClientSecret"]);

                string resource = ConfigurationManager.AppSettings["Resource"];
                return authContext.AcquireTokenSilent(resource, clientCredential, userId);
            }
            else
            {
                string clientId = ConfigurationManager.AppSettings["APIClientId"];
                string resource = ConfigurationManager.AppSettings["ClientId"];

                return authContext.AcquireTokenSilent(resource, clientId, userId);
            }
        }

        internal static AuthenticationResult GetTokenFromUserCredentials(string userName, string password)
        {
            IdentityModelEventSource.ShowPII = true;

            string authority = ConfigurationManager.AppSettings["AuthorityURI"];
            AuthenticationContext authContext = new AuthenticationContext(authority, new ADALTokenCache());

            UserCredential userCredential = new UserCredential(userName, password);
            string clientId = ConfigurationManager.AppSettings["APIClientId"];
            string resource = ConfigurationManager.AppSettings["ClientId"];

            return authContext.AcquireToken(resource, clientId, userCredential);
        }

        internal static ISecurityRole[] GetServerSecurityRolesFromToken(string userName)
        {
            List<ISecurityRole> userRoles = new List<ISecurityRole>();
            
            AuthenticationResult authResult = GetTokenFromCache(userName);
            JwtSecurityToken jwtToken;
            
            if (IsInteractiveAuth())
            {
                jwtToken = new JwtSecurityToken(authResult.IdToken);
            }
            else
            {
                jwtToken = OWINTokenValidation(authResult.AccessToken);
            }
            

            foreach (Claim claim in jwtToken.Claims.Where(claim => claim.Type == "roles"))
            { 
                switch (claim.Value)
                {
                    case "BrowserRole": 
                        userRoles.Add(new BrowserRole());
                        break;
                    case "ContentManagerRole":
                        userRoles.Add(new ContentManagerRole());
                        break;
                    case "MyReportsRole":
                        userRoles.Add(new MyReportsRole());
                        break;
                    case "PublisherRole":
                        userRoles.Add(new PublisherRole());
                        break;
                    case "ReportBuilderRole":
                        userRoles.Add(new ReportBuilderRole());
                        break;
                    case "SystemAdministratorRole":
                        userRoles.Add(new SystemAdministratorRole());
                        break;
                    case "SystemUserRole":
                        userRoles.Add(new SystemUserRole());
                        break;
                    default:
                        break;
                }
            }
            return userRoles.ToArray();
        }

        internal static string[] GetAllSecurityRolesFromToken(string userName)
        {
            List<ISecurityRole> userRoles = new List<ISecurityRole>();

            AuthenticationResult authResult = GetTokenFromCache(userName);
            JwtSecurityToken jwtToken = new JwtSecurityToken(authResult.IdToken);

            return jwtToken.Claims.Where(claim => claim.Type == "roles").Select(claim => claim.Value).ToArray();
        }

        private static bool IsInteractiveAuth()
        {
            //Determin if request is orignating from Portal or API
            //  - HttpContext is null when RSPortal is authenticating, not null for API's
            //  - ReportViewer.aspx is originated from Portal but calls api, override to obtain correct token
            return HttpContext.Current == null || HttpContext.Current.Request.Path == "/ReportServer/Pages/ReportViewer.aspx";
        }

        private static JwtSecurityToken OWINTokenValidation(string token)
        {
            string tenantId = ConfigurationManager.AppSettings["TenantId"];
            string stsDiscoveryEndpoint = String.Format("https://login.microsoftonline.com/{0}/v2.0/.well-known/openid-configuration", tenantId);

            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                   stsDiscoveryEndpoint,
                   new OpenIdConnectConfigurationRetriever()); 

            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync().Result;
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidAudience = "e3e62a63-870f-4df1-b6c4-3fab8a5365ec",
                ValidIssuer = String.Format("https://sts.windows.net/{0}/", tenantId),

                ValidateAudience = true,
                ValidateIssuer = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidateLifetime = true
            };

            JwtSecurityTokenHandler tokendHandler = new JwtSecurityTokenHandler();

            SecurityToken jwt;

            var result = tokendHandler.ValidateToken(token, validationParameters, out jwt);

            return jwt as JwtSecurityToken;
        }
    }
}