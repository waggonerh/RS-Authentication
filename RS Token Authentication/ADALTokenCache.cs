using System;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Web.Security;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace RSWebAuthentication
{
    internal class CachedUserToken
    {
        public int userTokenCacheId { get; set; }
        public byte[] cacheBits { get; set; }
        public DateTime lastWrite { get; set; }
    }

    /// <summary>
    /// Maintains a token cache store in a SQL DB
    /// </summary>
    internal class ADALTokenCache : TokenCache
    {
        private CachedUserToken cache;

        public ADALTokenCache()
        {
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            this.BeforeWrite = BeforeWriteNotification;
        }

        public override void Clear()
        {
            base.Clear();
        }

        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            if (cache == null)
            {
                cache = GetSQLCachedUserToken(args.ClientId, args.DisplayableId, args.Resource);
            }
            else
            {
                DateTime lastWrite = GetSQLCachedUserLastWrite(args.ClientId, args.DisplayableId, args.Resource);

                if (lastWrite > cache.lastWrite)
                {
                    cache = GetSQLCachedUserToken(args.ClientId, args.UniqueId, args.Resource);
                }
            }
            this.Deserialize((cache == null) ? null : MachineKey.Unprotect(cache.cacheBits, "ADALCache"));
        }

        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            if (this.HasStateChanged)
            {
                if (cache == null)
                {
                    cache = new CachedUserToken();
                }

                cache.cacheBits = MachineKey.Protect(this.Serialize(), "ADALCache");
                cache.lastWrite = DateTime.Now;

                if (cache.userTokenCacheId == 0)
                {
                    int cacheId = AddSQLCachedUserToken(args.ClientId, args.DisplayableId, args.Resource, cache);
                    cache.userTokenCacheId = cacheId;
                }
                else
                {
                    UpdateSQLCachedUserToken(cache);
                }

                this.HasStateChanged = false;
            }
        }

        void BeforeWriteNotification(TokenCacheNotificationArgs args)
        {

        }

        public override void DeleteItem(TokenCacheItem item)
        {
            base.DeleteItem(item);
        }

        #region SQL Commands
        private CachedUserToken GetSQLCachedUserToken(string clientId, string userId, string resource)
        {
            CachedUserToken sqlCachedUser;

            using (SqlConnection con = new SqlConnection(ConfigurationManager.AppSettings["TokenCacheSqlConnectionString"]))
            {
                SqlCommand cmd = new SqlCommand("extended.GetUserToken", con);
                cmd.Parameters.AddWithValue("@ClientId", clientId);
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.Parameters.AddWithValue("@Resource", resource);
                cmd.CommandType = CommandType.StoredProcedure;

                con.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    reader.Read();

                    sqlCachedUser = null;

                    if (reader.HasRows)
                    {
                        sqlCachedUser = new CachedUserToken();
                        sqlCachedUser.userTokenCacheId = reader.GetInt32(0);
                        sqlCachedUser.cacheBits = (byte[])reader.GetValue(1);
                        sqlCachedUser.lastWrite = reader.GetDateTime(2);
                    }
                }
            }

            return sqlCachedUser;
        }

        private DateTime GetSQLCachedUserLastWrite(string clientId, string userId, string resource)
        {
            DateTime lastWrite;

            using (SqlConnection con = new SqlConnection(ConfigurationManager.AppSettings["TokenCacheSqlConnectionString"]))
            {
                SqlCommand cmd = new SqlCommand("extended.GetUserTokenLastWrite", con);
                cmd.Parameters.AddWithValue("@ClientId", clientId);
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.Parameters.AddWithValue("@Resource", resource);
                cmd.CommandType = CommandType.StoredProcedure;

                con.Open();
                using (SqlDataReader reader = cmd.ExecuteReader())
                {
                    reader.Read();
                    if (reader.HasRows)
                    {
                        lastWrite = reader.GetDateTime(0);
                    }
                    else
                    {
                        lastWrite = DateTime.MinValue;
                    }
                    
                }
            }

            return lastWrite;
        }

        private void UpdateSQLCachedUserToken(CachedUserToken token)
        {
            using (SqlConnection con = new SqlConnection(ConfigurationManager.AppSettings["TokenCacheSqlConnectionString"]))
            {
                SqlCommand cmd = new SqlCommand("extended.UpdateUserToken", con);
                cmd.Parameters.AddWithValue("@UserTokenCacheId", token.userTokenCacheId);
                cmd.Parameters.AddWithValue("@CachedBits", token.cacheBits);
                cmd.Parameters.AddWithValue("@LastWrite", token.lastWrite);

                cmd.CommandType = CommandType.StoredProcedure;

                con.Open();
                cmd.ExecuteNonQuery();
            }
        }

        private int AddSQLCachedUserToken(string clientId, string userId, string resource, CachedUserToken token)
        {
            int cacheId;

            using (SqlConnection con = new SqlConnection(ConfigurationManager.AppSettings["TokenCacheSqlConnectionString"]))
            {
                SqlCommand cmd = new SqlCommand("extended.AddUserToken", con);
                cmd.Parameters.AddWithValue("@ClientId", clientId);
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.Parameters.AddWithValue("@Resource", resource);
                cmd.Parameters.AddWithValue("@CachedBits", token.cacheBits);
                cmd.Parameters.AddWithValue("@LastWrite", token.lastWrite);

                SqlParameter UserTokenCacheIdParam = new SqlParameter("@UserTokenCacheId", SqlDbType.Int);
                UserTokenCacheIdParam.Direction = ParameterDirection.Output;
                cmd.Parameters.Add(UserTokenCacheIdParam);

                cmd.CommandType = CommandType.StoredProcedure;

                con.Open();
                cmd.ExecuteNonQuery();

                cacheId = (int)cmd.Parameters["@UserTokenCacheId"].Value;
            }

            return cacheId;
        }

        private void ClearSQLCachedUserToken(string clientId, string userId, string resource)
        {
            using (SqlConnection con = new SqlConnection(ConfigurationManager.AppSettings["TokenCacheSqlConnectionString"]))
            {
                SqlCommand cmd = new SqlCommand("extended.ClearUserToken", con);
                cmd.Parameters.AddWithValue("@ClientId", clientId);
                cmd.Parameters.AddWithValue("@UserId", userId);
                cmd.Parameters.AddWithValue("@Resource", resource);
                cmd.CommandType = CommandType.StoredProcedure;

                con.Open();
                cmd.ExecuteNonQuery();
            }
        }
        #endregion
    }
}
