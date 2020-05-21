using CSharp_easy_RSA_PEM;
using Jose;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Middleware.Target.TPlus_V12_3.Models.TPlusClass
{
    public class SignatureManage
    {
        /// <summary>
        /// 签名方式1
        /// </summary>
        /// <param name="data">签名内容的json串格式</param>
        /// <param name="pemFile">私钥文件物理路径</param>
        /// <returns></returns>
        public string CreateSignedToken(string data, string pemFile)
        {
            var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            //5分钟内有效
            var exp = ts.TotalMilliseconds + 30000;

            var payload = new Dictionary<string, object>
            {
                {"sub", "tester"},
                {"exp", exp},
                {"datas", GetMd5(data)}
            };
            //string loadedRSA = File.ReadAllText("keys/private.rsa.pem");
            string loadedRSA = File.ReadAllText(pemFile);
            RSACryptoServiceProvider privateRSAkey = Crypto.DecodeRsaPrivateKey(loadedRSA);
            var token = JWT.Encode(payload, privateRSAkey, JwsAlgorithm.PS256);
            return token;
        }
        /// <summary>
        /// 签名方式2
        /// </summary>
        /// <param name="data">签名内容的json串格式</param>
        /// <param name="pemFile">私钥文件物理路径</param>
        /// <param name="customparas">签名附加内容</param>
        /// <returns></returns>
        public string CreateSignedToken(string data, string pemFile, IDictionary<string, object> customparas)
        {
            var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            //5分钟内有效
            var exp = ts.TotalMilliseconds + 30000;

            var payload = new Dictionary<string, object>
            {
                {"sub", "chanjet"},
                {"exp", exp},
                {"datas", GetMd5(data)}
            };
            foreach (string key in customparas.Keys)
            {
                payload.Add(key, customparas[key]);
            }
            //string loadedRSA = File.ReadAllText("keys/private.rsa.pem");
            string loadedRSA = File.ReadAllText(pemFile);
            RSACryptoServiceProvider privateRSAkey = Crypto.DecodeRsaPrivateKey(loadedRSA);
            var token = JWT.Encode(payload, privateRSAkey, JwsAlgorithm.PS256);
            return token;
        }

        /// <summary>
        /// 获取md5值
        /// </summary>
        /// <param name="requestdatas"></param>
        /// <returns></returns>
        public string GetMd5(string requestdatas)
        {
            hashCryptography hash = new hashCryptography(HashProvider.MD5);
            return hash.HashString(requestdatas);

        }
        /// <summary>
        /// 生成Authorization头，根据token传值与否，决定采用签名方式1  还是签名方式2
        /// </summary>
        /// <param name="appKey"></param>
        /// <param name="appSecret"></param>
        /// <param name="orgId"></param>
        /// <param name="pemFile">私钥文件物理路径</param>
        /// <param name="token">获取到的token值</param>
        /// <returns></returns>
        public string CreateAuthorizationHeader(string appKey, string appSecret, string orgId, string pemFile, string token)
        {
            var dic = new Dictionary<string, object>
            {
                {"appkey", appKey},
                {"orgid",orgId},
                {"appsecret", appSecret}
            };
            var datas = JsonConvert.SerializeObject(dic);
            var signStr = string.Empty;
            if (string.IsNullOrWhiteSpace(token))
                signStr = this.CreateSignedToken(datas, pemFile);//签名方式1
            else
                signStr = this.CreateSignedToken(datas, pemFile, new Dictionary<string, object>() { { "access_token", token } });//签名方式2
            dic = new Dictionary<string, object>
            {
                {"appKey",appKey },
                { "authInfo",signStr},
                { "orgId",orgId}
            };
            var authStr = JsonConvert.SerializeObject(dic);
            string encode = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(authStr));
            return encode;
        }
    }
}
