using Chanjet.TP.OpenAPI;
using CloudField.Framework.Extensions;
using CSharp_easy_RSA_PEM;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Middleware.DataTransport.Core.API;
using Middleware.Target.TPlus_V12_3.Models.TPlusClass;
using Middleware.Target.TPlus_V12_3.Request;
using Middleware.Target.TPlus_V12_3.Response;
using RestSharp.Serializers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Ufida.T.EAP.Aop.Util;

namespace Middleware.Target.TPlus_V12_3
{
    public class TPlusClient : BaseAPIClient
    {
        IMemoryCache memoryCache = new MemoryCache(Options.Create(new MemoryCacheOptions()));

        public TPlusClient(BaseAPIConfig apiConfig) : base(apiConfig)
        {
            if (APIConfig.NeedAuthorize)
            {
                APIConfig.AddConfigDefine(new ConfigDefine { Name = "Authorization", Type = ConfgDefineType.Header, ValueMethod = () => GetAuthorizationFromCache() });
                APIConfig.AddConfigDefine(new ConfigDefine { Name = "Accept", Type = ConfgDefineType.Header, Value = "application/json, application/xml, text/json, text/x-json, text/javascript, text/xml" });
            }

        }
        public string GetAuthorizationFromCache()
        {
            var cache = memoryCache.GetOrCreate<string>("token", (x) => GetToken(x));
            return cache;
        }
        public AccessTokenResponse GetAccessToken()
        {
            if (!APIConfig.AuthorizeParameters.ContainsKey("appkey")
                || !APIConfig.AuthorizeParameters.ContainsKey("orgid")
                || !APIConfig.AuthorizeParameters.ContainsKey("appsecret")
                || !APIConfig.AuthorizeParameters.ContainsKey("secerturl"))
            {
                throw new Exception("鉴权参数不完整");
            }
            var request = new AccessTokenRequest();
            Dictionary<string, object> parm = new Dictionary<string, object>();
            string appkey = APIConfig.AuthorizeParameters["appkey"];
            string orgid = APIConfig.AuthorizeParameters["orgid"];
            string appsecret = APIConfig.AuthorizeParameters["appsecret"];
            string secetrurl = APIConfig.AuthorizeParameters["secerturl"];

            parm.Add("appkey", appkey);
            parm.Add("orgid", orgid);
            parm.Add("appsecret", appsecret);

            JsonSerializer jsonSerializer = new JsonSerializer();
            string datas = jsonSerializer.Serialize(parm);
            try
            {
                var signClass = new TokenManage();
                string signvalue = signClass.CreateSignedToken(datas, secetrurl);
                string authStr = @"{""appKey"":""" + appkey + @""",""authInfo"":""" + signvalue + @""",""orgId"":" + orgid + @"}";
                string encode = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(authStr));
                Dictionary<string, string> parms = new Dictionary<string, string>();
                parms.Add("Authorization", encode);
                request.SetHeaderParameters(parms);
                var response = Excute(request);
                return response;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
        public string GetAuthorization(string tokenStr)
        {
            Dictionary<string, object> parm = new Dictionary<string, object>();
            string appkey = APIConfig.AuthorizeParameters["appkey"];
            string orgid = APIConfig.AuthorizeParameters["orgid"];
            string appsecret = APIConfig.AuthorizeParameters["appsecret"];
            string secetrurl = APIConfig.AuthorizeParameters["secerturl"];
            if (string.IsNullOrEmpty(secetrurl) || !File.Exists(secetrurl))
            {
                throw new Exception("请指定私钥路径！");
            }
            if (!APIConfig.AuthorizeParameters["userName"].IsNullOrEmpty())
            {
                orgid = "";
            }
            parm.Add("appkey", appkey);
            parm.Add("orgid", orgid);
            parm.Add("appsecret", appsecret);
            //业务请求的Authorization
            var customParas = new Dictionary<string, object>
                { {"access_token", tokenStr} };
            JsonSerializer jsonSerializer = new JsonSerializer();
            string bizdatas = jsonSerializer.Serialize(parm);
            var signClass = new TokenManage();
            try
            {
                string bizAuthorization = signClass.CreateSignedToken(bizdatas, secetrurl, customParas);
                string authStr1 = @"{""appKey"":""" + appkey + @""",""authInfo"":""" + bizAuthorization + @""",""orgId"":" + (!orgid.IsNullOrEmpty() ? orgid : @"""""") + @"}";
                string encode1 = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(authStr1));
                return encode1;
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }
        }
        public string GetToken(ICacheEntry cache)
        {
            APIConfig.ConfigDefines.ForEach(t =>
            {
                t.Disabled = true;
            });
            var tokenStr = "";
            if (APIConfig.AuthorizeParameters["orgid"].IsNullOrEmpty() && !APIConfig.AuthorizeParameters["userName"].IsNullOrEmpty())
            {
                var tokenData = GetAccessTokenByPwd();
                tokenStr = tokenData.access_token;
            }
            else if (!APIConfig.AuthorizeParameters["orgid"].IsNullOrEmpty() && APIConfig.AuthorizeParameters["userName"].IsNullOrEmpty())
            {
                var tokenData = GetAccessToken();
                tokenStr = tokenData.access_token;
            }

            cache.Value = tokenStr;
            cache.SetAbsoluteExpiration(TimeSpan.FromSeconds(1200));
            APIConfig.ConfigDefines.ForEach(x =>
            {
                x.Disabled = false;
            });
            return GetAuthorization(tokenStr);
        }
        public string GetMD5(string str)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(str);
            try
            {
                MD5CryptoServiceProvider check;
                check = new MD5CryptoServiceProvider();
                byte[] somme = check.ComputeHash(buffer);
                string ret = "";
                foreach (byte a in somme)
                {
                    if (a < 16)
                        ret += "0" + a.ToString("X");
                    else
                        ret += a.ToString("X");
                }
                return ret;
            }
            catch
            {
                throw;
            }
        }

        public GetTokenByPwdResponse GetAccessTokenByPwd()
        {
            if (!APIConfig.AuthorizeParameters.ContainsKey("appkey")
               || !APIConfig.AuthorizeParameters.ContainsKey("appsecret")
               || !APIConfig.AuthorizeParameters.ContainsKey("secerturl")
               || !APIConfig.AuthorizeParameters.ContainsKey("userName")
                || !APIConfig.AuthorizeParameters.ContainsKey("password")
                 || !APIConfig.AuthorizeParameters.ContainsKey("accNum")
                 )
            {
                throw new Exception("鉴权参数不完整");
            }
            var signClass = new TokenManage();
            var request = new GetTokenByPwdRequest();
            string appkey = APIConfig.AuthorizeParameters["appkey"];
            string appsecret = APIConfig.AuthorizeParameters["appsecret"];
            string secetrurl = APIConfig.AuthorizeParameters["secerturl"];
            string userName = APIConfig.AuthorizeParameters["userName"];
            string password = APIConfig.AuthorizeParameters["password"];
            string EncodePassword = signClass.GetMd5(password);
            string accNum = APIConfig.AuthorizeParameters["accNum"];

            Dictionary<string, object> parm = new Dictionary<string, object>();
            parm.Add("appkey", appkey);
            parm.Add("orgid", "");
            parm.Add("appsecret", appsecret);

            JsonSerializer jsonSerializer = new JsonSerializer();
            string datas = jsonSerializer.Serialize(parm);
            try
            {
                string signvalue = signClass.CreateSignedToken(datas, secetrurl);
                string authStr = @"{""appKey"":""" + appkey + @""",""authInfo"":""" + signvalue + @""",""orgId"":""""}";
                string encode = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(authStr));
                Dictionary<string, string> parms = new Dictionary<string, string>();
                parms.Add("Authorization", encode);
                request.SetHeaderParameters(parms);

                Dictionary<string, object> postParms = new Dictionary<string, object>();
                var args = new PwdEntity() { userName = userName, password = EncodePassword, accNum = accNum };
                var argsJson = jsonSerializer.Serialize(args);
                postParms.Add("_args", argsJson);
                request.SetPostParameters(postParms);

                var response = Excute(request);
                return response;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
    }

}
