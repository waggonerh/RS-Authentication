using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Configuration;
using System.Web;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Graph;
using System.Net.Http.Headers;

namespace RSWebAuthentication
{
    internal enum AllowedSecurityTypes
    {
        Users,
        Groups,
        Roles
    }

    internal enum TokenTypes
    {
        Id,
        Access,
        Default
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
                jwtToken = new JwtSecurityToken(authResult.IdToken);
            }
            else
            {
                string clientId = ConfigurationManager.AppSettings["APIClientId"];
                resource = ConfigurationManager.AppSettings["ClientId"];

                authResult = authContext.AcquireTokenSilent(resource, clientId, userId);
                jwtToken = OWINTokenValidation(authResult.IdToken, resource);
            }

            return jwtToken;
        }

        internal static JwtSecurityToken GetCachedGraphToken(string userName)
        {
            AuthenticationContext authContext = new AuthenticationContext(ConfigurationManager.AppSettings["AuthorityURI"], new ADALTokenCache());
            UserIdentifier userId = new UserIdentifier(userName, UserIdentifierType.RequiredDisplayableId);
            AuthenticationResult authResult;
            string resource = TokenUtilities.GraphResourceId;
            JwtSecurityToken jwtToken;

            if (IsInteractiveAuth())
            {
                ClientCredential clientCredential = new ClientCredential(
                    ConfigurationManager.AppSettings["ClientID"],
                    ConfigurationManager.AppSettings["ClientSecret"]);

                authResult = authContext.AcquireTokenSilent(resource, clientCredential, userId);
            }
            else
            {
                string clientId = ConfigurationManager.AppSettings["APIClientId"];

                authResult = authContext.AcquireTokenSilent(resource, clientId, userId);
            }

            jwtToken = new JwtSecurityToken(authResult.AccessToken);

            return jwtToken;
        }

        internal static string[] GetAllClaimsFromToken(string userName, string claimType)
        {
            JwtSecurityToken jwtToken = GetCachedIdToken(userName);
            return jwtToken.Claims.Where(claim => claim.Type.Equals(claimType, StringComparison.OrdinalIgnoreCase)).Select(claim => claim.Value).ToArray();
        }

        internal static string[] GetAllGroupsForUser(string userName)
        {
            //If groups are utilized, report executino will hang with the Loading popup indefinitely.
            // This is an async/await issue between the background service and the rsportal.exe.
            throw new NotImplementedException();

            List<string> groups = new List<string>();

            JwtSecurityToken token = TokenUtilities.GetCachedGraphToken(userName);

            GraphServiceClient client = new GraphServiceClient("https://graph.microsoft.com/v1.0",
                new DelegateAuthenticationProvider(
                    async (requestMessage) =>
                    {
                        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("bearer", token.RawData);
                    }));

            //Issue lies here:
            IUserMemberOfCollectionWithReferencesPage memberOf =
                client.Me.MemberOf.Request().Select("displayName").GetAsync().Result;

            while (memberOf.Count > 0)
            {
                foreach (Group group in memberOf.CurrentPage.OfType<Group>())
                {
                    groups.Add(group.DisplayName);
                }

                if (memberOf.NextPageRequest != null)
                {
                    memberOf = memberOf.NextPageRequest.GetAsync().Result;
                }
                else
                {
                    break;
                }
            }

            return groups.ToArray();
        }

        private static bool IsInteractiveAuth()
        {
            //Determin if request is orignating from Portal or API
            //  - HttpContext is null when RSPortal is authenticating, not null for API's
            //  - ReportViewer.aspx is originated from Portal but calls api, override to obtain correct token
            return HttpContext.Current == null
                || HttpContext.Current.Request.Path.Equals("/ReportServer/Pages/ReportViewer.aspx", StringComparison.OrdinalIgnoreCase)
                || HttpContext.Current.Request.Path.Equals("/ReportServer/Reserved.ReportViewerWebControl.axd", StringComparison.OrdinalIgnoreCase);
        }

        private static JwtSecurityToken OWINTokenValidation(string token, string audience)
        {
            string tenantId = ConfigurationManager.AppSettings["TenantId"];
            string stsDiscoveryEndpoint = String.Format("https://login.microsoftonline.com/{0}/v2.0/.well-known/openid-configuration", tenantId);

            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                   stsDiscoveryEndpoint,
                   new OpenIdConnectConfigurationRetriever());

            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync().Result;
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidAudience = audience,
                ValidIssuer = String.Format("https://sts.windows.net/{0}/", tenantId),

                ValidateAudience = true,
                ValidateIssuer = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidateLifetime = true
            };

            JwtSecurityTokenHandler tokendHandler = new JwtSecurityTokenHandler();

            SecurityToken jwt;

            ClaimsPrincipal result = tokendHandler.ValidateToken(token, validationParameters, out jwt);

            return jwt as JwtSecurityToken;
        }
    }
}