using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace RSWebAuthentication.Graph
{
    public class User
    {
        private User() { }

        [JsonProperty("userPrincipalName")]
        public string UserPrincipalName { get; set; }

        public static List<User> GetUsers(string userName)
        {
            const string uriTemplate = "https://graph.microsoft.com/v1.0/users?$filter=userPrincipalName eq '{0}'&$select=userPrincipalName&$format=application/json;odata=nometadata";
            string uri = string.Format(uriTemplate, userName);

            JwtSecurityToken token = TokenUtilities.GetTokenFromClientCredentials("https://graph.microsoft.com/");

            HttpWebRequest request = WebRequest.CreateHttp(uri);
            request.Method = "GET";
            request.ContentType = "application/json";
            request.Headers.Add("Authorization", token.RawData);

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                using (Stream responseStream = response.GetResponseStream())
                {
                    using (StreamReader reader = new StreamReader(responseStream, Encoding.UTF8))
                    {
                        string responseJson = reader.ReadToEnd();

                        GraphResults results = JsonConvert.DeserializeObject<GraphResults>(responseJson);
                        return results.Users;
                    }
                }
            }
        }

        private partial class GraphResults
        {
            [JsonProperty("@odata.context")]
            public Uri OdataContext { get; set; }

            [JsonProperty("value")]
            public List<User> Users { get; set; }
        }
    }
}