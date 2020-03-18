using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace RSWebAuthentication.Graph
{
    public partial class AppRole
    {
        private AppRole() { }

        [JsonProperty("allowedMemberTypes")]
        public List<string> AllowedMemberTypes { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("displayName")]
        public string DisplayName { get; set; }

        [JsonProperty("id")]
        public Guid Id { get; set; }

        [JsonProperty("isEnabled")]
        public bool IsEnabled { get; set; }

        [JsonProperty("origin")]
        public string Origin { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }

        public static List<AppRole> GetRolesForApplication(string appId)
        {
            const string uriTemplate = "https://graph.microsoft.com/v1.0/applications?$filter=appId eq '{0}'&$select=appRoles&$format=application/json;odata=nometadata";
            string uri = string.Format(uriTemplate, appId);

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
                        return results.Applications.FirstOrDefault().AppRoles;
                    }
                }
            }
        }

        private partial class GraphResults
        {
            [JsonProperty("@odata.context")]
            public Uri OdataContext { get; set; }

            [JsonProperty("value")]
            public List<Application> Applications { get; set; }
        }

        private partial class Application
        {
            [JsonProperty("appRoles")]
            public List<AppRole> AppRoles { get; set; }
        }
    }
}