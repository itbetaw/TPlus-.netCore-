using CSharp_easy_RSA_PEM;
using Jose;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Ufida.T.EAP.Net;
using Ufida.T.EAP.Net.security;

namespace Middleware.Target.TPlus_V12_3.Models.TPlusClass
{
    public class TokenManage
    {
        public TokenManage()
        {
        }

        private string BuildParas(IDictionary<string, string> paras)
        {
            StringBuilder stringBuilder = new StringBuilder();
            if (paras != null && paras.Count > 0)
            {
                int num = 0;
                foreach (string key in paras.Keys)
                {
                    if (num <= 0)
                    {
                        stringBuilder.AppendFormat("{0}={1}", key, Uri.EscapeDataString(paras[key]));
                    }
                    else
                    {
                        stringBuilder.AppendFormat("&{0}={1}", key, Uri.EscapeDataString(paras[key]));
                    }
                    num++;
                }
            }
            return stringBuilder.ToString();
        }

        public string CreateSignedToken(string data, string pemFile)
        {
            TimeSpan utcNow = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            double totalMilliseconds = utcNow.TotalMilliseconds + 30000;
            Dictionary<string, object> strs = new Dictionary<string, object>()
            {
                { "sub", "tester" },
                { "exp", totalMilliseconds },
                { "datas", this.GetMd5(data) }
            };
            Dictionary<string, object> strs1 = strs;
            RSACryptoServiceProvider rSACryptoServiceProvider = Crypto.DecodeRsaPrivateKey(File.ReadAllText(pemFile), "");
            return JWT.Encode(strs1, rSACryptoServiceProvider, JwsAlgorithm.PS256, null);
        }

        public string CreateSignedToken(string data, string pemFile, IDictionary<string, object> customparas)
        {
            TimeSpan utcNow = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            double totalMilliseconds = utcNow.TotalMilliseconds + 30000;
            Dictionary<string, object> strs = new Dictionary<string, object>()
            {
                { "sub", "chanjet" },
                { "exp", totalMilliseconds },
                { "datas", this.GetMd5(data) }
            };
            Dictionary<string, object> strs1 = strs;
            foreach (string key in customparas.Keys)
            {
                strs1.Add(key, customparas[key]);
            }
            RSACryptoServiceProvider rSACryptoServiceProvider = Crypto.DecodeRsaPrivateKey(File.ReadAllText(pemFile), "");
            return JWT.Encode(strs1, rSACryptoServiceProvider, JwsAlgorithm.PS256, null);
        }

        public IDictionary<string, object> GetCustomParaFromToken(string token, string src, string pemFile, List<string> keys)
        {
            IDictionary<string, object> strs;
            IDictionary<string, object> strs1 = new Dictionary<string, object>();
            try
            {
                string str = File.ReadAllText(pemFile);
                Dictionary<string, object> strs2 = JWT.Decode<Dictionary<string, object>>(token, Crypto.DecodeX509PublicKey(str));
                object item = strs2["datas"];
                Console.WriteLine(string.Format(item.ToString(), new object[0]));
                if (object.Equals(this.GetMd5(src), item))
                {
                    foreach (string key in keys)
                    {
                        strs1.Add(key, strs2[key]);
                    }
                }
                strs = strs1;
            }
            catch (Exception exception)
            {
                LoggerAdapter.Error(string.Format("ValidateToken fail:{0}", exception.Message));
                strs = strs1;
            }
            return strs;
        }

        public string GetMd5(string requestdatas)
        {
            return (new hashCryptography(HashProvider.MD5)).HashString(requestdatas);
        }

        public bool ValidateToken(string token, string src, string pemFile)
        {
            bool flag;
            try
            {
                RSACryptoServiceProvider rSACryptoServiceProvider = Crypto.DecodeX509PublicKey(File.ReadAllText(pemFile));
                object item = JWT.Decode<Dictionary<string, object>>(token, rSACryptoServiceProvider)["datas"];
                Console.WriteLine(string.Format(item.ToString(), new object[0]));
                flag = object.Equals(this.GetMd5(src), item);
            }
            catch (Exception exception)
            {
                LoggerAdapter.Error(string.Format("ValidateToken fail:{0}", exception.Message));
                flag = false;
            }
            return flag;
        }
    }

}
