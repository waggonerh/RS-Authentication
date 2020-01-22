using System;
using System.Data;
using System.Data.SqlClient;
using System.Security.Principal;
using System.Web;
using Microsoft.ReportingServices.Interfaces;
using System.Globalization;
using System.Xml;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace RSWebAuthentication
{
    /// <summary>
    /// Implements RS IAuthenticationExtension2
    /// </summary>
    public class AuthenticationExtension : IAuthenticationExtension2, IExtension
    {
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
                userIdentity = null;;
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
            throw new NotImplementedException();
        }

        /// <summary>
        /// Called when authenticating to the API (non-interactive redirect). Uses the resource owner grant flow to obtain a token.
        /// </summary>
        public bool LogonUser(string userName, string password, string authority)
        {
            AuthenticationResult authResult = null;

            if (!string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(password))
            {
                authResult = TokenUtilities.GetTokenFromUserCredentials(userName, password);
            }
            
            return authResult != null;
        }

        public void SetConfiguration(string configuration)
        {

        }
    }
}