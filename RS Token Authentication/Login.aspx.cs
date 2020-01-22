using System;
using System.Collections.Specialized;
using System.Web;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Web.Security;
using System.Configuration;
using System.Linq;

namespace RSWebAuthentication
{
    public partial class Login : System.Web.UI.Page
    {
        AuthenticationResult authResult = null;
        protected void Page_Load(object sender, EventArgs e)
        {
            // On initial load, redirects to AAD for an auth token.
            // On second load (redirect from AAD), redeems the auth token for an access token.

            string error = null;
            string errorDesc = null;

            if (Request.Params.AllKeys.Contains("error"))
            {
                error = Request.Params.GetValues("error")[0];
                errorDesc = Request.Params.GetValues("error_description")[0];
            }
            else if (Request.Params.AllKeys.Contains("code"))
            {
                string code = Request.Params.GetValues("code")[0];
                authResult = TokenUtilities.GetTokenFromAuthCode(code);
            }

            if (authResult == null)
            {
                RedirectToAuthority();
            }
            else
            {
                FormsAuthentication.SetAuthCookie(authResult.UserInfo.DisplayableId, true);
                Response.Redirect("/Reports");
            }
        }

        private void RedirectToAuthority()
        {
            var @params = new NameValueCollection
            {
                {"response_type", "code"},
                {"client_id", ConfigurationManager.AppSettings["ClientID"]},
                {"redirect_uri", ConfigurationManager.AppSettings["RedirectURI"]},
                {"scope", "User.Read"}
            };

            var queryString = HttpUtility.ParseQueryString(string.Empty);
            queryString.Add(@params);

            string authorityUri = ConfigurationManager.AppSettings["AuthorizeURI"];
            var authUri = String.Format("{0}?{1}", authorityUri, queryString);
            Response.Redirect(authUri);
        }
    }
}