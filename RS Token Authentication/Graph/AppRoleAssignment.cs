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
    public partial class AppRoleAssignment
    {
        private AppRoleAssignment() { }

        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("creationTimestamp")]
        public DateTimeOffset CreationTimestamp { get; set; }

        [JsonProperty("appRoleId")]
        public Guid AppRoleId { get; set; }

        [JsonProperty("principalDisplayName")]
        public string PrincipalDisplayName { get; set; }

        [JsonProperty("principalId")]
        public Guid PrincipalId { get; set; }

        [JsonProperty("principalType")]
        public string PrincipalType { get; set; }

        [JsonProperty("resourceDisplayName")]
        public string ResourceDisplayName { get; set; }

        [JsonProperty("resourceId")]
        public Guid ResourceId { get; set; }


        public static List<AppRoleAssignment> GetAssignedRolesForUser(string userName, string enterpiseAppId)
        {
            const string uriTemplate = "https://graph.microsoft.com/beta/users/{0}/appRoleAssignments?filter=resourceId eq {1}&format=application/json;odata=nometadata";
            string uri = string.Format(uriTemplate, userName, enterpiseAppId);

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
                        return results.AppRoleAssignments;
                    }
                }
            }
        }

        private partial class GraphResults
        {
            [JsonProperty("@odata.context")]
            public Uri OdataContext { get; set; }

            [JsonProperty("value")]
            public List<AppRoleAssignment> AppRoleAssignments { get; set; }
        }

    }
}