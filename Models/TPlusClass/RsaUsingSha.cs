using Jose;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Middleware.Target.TPlus_V12_3.Models.TPlusClass
{
    public class RsaUsingSha : IJwsAlgorithm
    {
        private string hashMethod;

        private System.Security.Cryptography.HashAlgorithm HashAlgorithm
        {
            get
            {
                if (this.hashMethod.Equals("SHA256"))
                {
                    return SHA256.Create();
                }
                if (this.hashMethod.Equals("SHA384"))
                {
                    return SHA384.Create();
                }
                if (!this.hashMethod.Equals("SHA512"))
                {
                    throw new ArgumentException("Unsupported hashing algorithm: '{0}'", this.hashMethod);
                }
                return SHA512.Create();
            }
        }

        public RsaUsingSha(string hashMethod)
        {
            this.hashMethod = hashMethod;
        }

        public byte[] Sign(byte[] securedInput, object key)
        {
            byte[] numArray;
            RSA rSA = Ensure.Type<RSA>(key, "RsaUsingSha alg expects key to be of AsymmetricAlgorithm type.", new object[0]);
            using (System.Security.Cryptography.HashAlgorithm hashAlgorithm = this.HashAlgorithm)
            {
                RSAPKCS1SignatureFormatter rSAPKCS1SignatureFormatter = new RSAPKCS1SignatureFormatter(rSA);
                rSAPKCS1SignatureFormatter.SetHashAlgorithm(this.hashMethod);
                numArray = rSAPKCS1SignatureFormatter.CreateSignature(hashAlgorithm.ComputeHash(securedInput));
            }
            return numArray;
        }

        public bool Verify(byte[] signature, byte[] securedInput, object key)
        {
            bool flag;
            using (System.Security.Cryptography.HashAlgorithm hashAlgorithm = this.HashAlgorithm)
            {
                AsymmetricAlgorithm asymmetricAlgorithm = Ensure.Type<AsymmetricAlgorithm>(key, "RsaUsingSha alg expects key to be of AsymmetricAlgorithm type.", new object[0]);
                byte[] numArray = hashAlgorithm.ComputeHash(securedInput);
                RSAPKCS1SignatureDeformatter rSAPKCS1SignatureDeformatter = new RSAPKCS1SignatureDeformatter(asymmetricAlgorithm);
                rSAPKCS1SignatureDeformatter.SetHashAlgorithm(this.hashMethod);
                flag = rSAPKCS1SignatureDeformatter.VerifySignature(numArray, signature);
            }
            return flag;
        }
    }
}
