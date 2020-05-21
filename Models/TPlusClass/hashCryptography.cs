using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Middleware.Target.TPlus_V12_3.Models.TPlusClass
{

    public enum HashProvider : int
    {
        SHA1 = 1,
        MD5 = 2,
        SHA256 = 4,
        SHA384 = 8,
        SHA512 = 16
    }

    public class hashCryptography
    {
        private HashProvider _provider = HashProvider.SHA1;
        private HashAlgorithm mhash;
        private bool m_IsAddSalt = false;
        string m_SaltValue = String.Empty;
        short m_SaltLength = 8;
        public bool IsAddSalt
        {
            get
            {
                return m_IsAddSalt;
            }
            set
            {
                m_IsAddSalt = value;
            }
        }
        public short SaltLength
        {
            get { return m_SaltLength; }
            set { m_SaltLength = value; }
        }
        public string SaltValue
        {
            get { return m_SaltValue; }
            set { m_SaltValue = value; }
        }
        public hashCryptography()
        {
            //
            mhash = SetHash();
            //
        }
        /// <summary>
        /// hashCryptography 构造函数，可以指明加密的算法
        /// </summary>
        public hashCryptography(HashProvider provider)
        {
            //
            _provider = provider;
            mhash = SetHash();
            //
        }
        /// <summary>
        /// 根据加密算法，决定使用哪个加密服务提供程序并创建该方法的实例
        /// </summary>
        private HashAlgorithm SetHash()
        {
            HashAlgorithm hashProv;
            switch (_provider)
            {
                case HashProvider.SHA1:
                    hashProv = new SHA1CryptoServiceProvider();
                    break;
                case HashProvider.MD5:
                    hashProv = new MD5CryptoServiceProvider();
                    break;
                case HashProvider.SHA256:
                    hashProv = new SHA256Managed();
                    break;
                case HashProvider.SHA384:
                    hashProv = new SHA384Managed();
                    break;
                case HashProvider.SHA512:
                    hashProv = new SHA512Managed();
                    break;
                default:
                    hashProv = new SHA1CryptoServiceProvider();
                    break;
            }

            return hashProv;
        }
        /// <summary>
        /// 加密字符串，并以base64的编码方式输出
        /// </summary>
        //public string HashString(string Value)
        //{

        //    if (m_IsAddSalt)
        //    {
        //        if (m_SaltValue.Length == 0)
        //            m_SaltValue = this.CreateSalt();
        //    }
        //    else
        //    {
        //        m_SaltValue = string.Empty;
        //    }
        //    // 将原始字符串转换成字节数组
        //    byte[] bytValue = System.Text.Encoding.UTF8.GetBytes(Value + m_SaltValue);

        //    // 计算散列，并返回一个字节数组
        //    byte[] bytHash = mhash.ComputeHash(bytValue);

        //    mhash.Clear();

        //    // 返回散列值
        //    return Convert.ToBase64String(bytHash);
        //}
        public string HashString(string Value)
        {

            if (m_IsAddSalt)
            {
                if (m_SaltValue.Length == 0)
                    m_SaltValue = this.CreateSalt();
            }
            else
            {
                m_SaltValue = string.Empty;
            }
            // 将原始字符串转换成字节数组
            byte[] bytValue = System.Text.Encoding.UTF8.GetBytes(Value + m_SaltValue);

            // 计算散列，并返回一个字节数组
            byte[] bytHash = mhash.ComputeHash(bytValue);

            mhash.Clear();
            var sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (var i = 0; i < bytHash.Length; i++)
            {
                sBuilder.AppendFormat("{0:x2}", bytHash[i]);
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();

        }
        public void Reset()
        {
            m_SaltValue = String.Empty;
            _provider = HashProvider.SHA1;
            m_IsAddSalt = false;
            m_SaltLength = 8;
            mhash = null;
        }

        /// <summary>
        /// 生成散列的盐值
        /// </summary>
        public string CreateSalt()
        {
            byte[] bytSalt = new byte[8];
            RNGCryptoServiceProvider rng;

            rng = new RNGCryptoServiceProvider();

            rng.GetBytes(bytSalt);

            return Convert.ToBase64String(bytSalt);
        }
    }
}
