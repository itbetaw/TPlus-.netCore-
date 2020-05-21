using Jose.native;
using System;
using System.Security.Cryptography;

namespace Jose
{
    public static class RsaPss
    {
        private static HashAlgorithm HashAlgorithm(CngAlgorithm hash)
        {
            if (hash == CngAlgorithm.Sha256)
            {
                return SHA256.Create();
            }
            if (hash == CngAlgorithm.Sha384)
            {
                return SHA384.Create();
            }
            if (hash != CngAlgorithm.Sha512)
            {
                throw new ArgumentException(string.Format("RsaPss expects hash function to be SHA256, SHA384 or SHA512, but was given:{0}", hash));
            }
            return SHA512.Create();
        }

        public static byte[] Sign(byte[] input, CngKey key, CngAlgorithm hash, int saltSize)
        {
            byte[] numArray;
            using (HashAlgorithm hashAlgorithm = RsaPss.HashAlgorithm(hash))
            {
                numArray = RsaPss.SignHash(hashAlgorithm.ComputeHash(input), key, hash.Algorithm, saltSize);
            }
            return numArray;
        }

        private static byte[] SignHash(byte[] hash, CngKey key, string algorithm, int saltSize)
        {
            BCrypt.BCRYPT_PSS_PADDING_INFO bcrypt_PSS_PADDING_INFO = new BCrypt.BCRYPT_PSS_PADDING_INFO(algorithm, saltSize);
            uint num2;
            uint num = NCrypt.NCryptSignHash(key.Handle, ref bcrypt_PSS_PADDING_INFO, hash, hash.Length, null, 0, out num2, 8u);
            if (num != 0u)
            {
                throw new CryptographicException(string.Format("NCrypt.NCryptSignHash() (signature size) failed with status code:{0}", num));
            }
            byte[] array = new byte[num2];
            num = NCrypt.NCryptSignHash(key.Handle, ref bcrypt_PSS_PADDING_INFO, hash, hash.Length, array, array.Length, out num2, 8u);
            if (num != 0u)
            {
                throw new CryptographicException(string.Format("NCrypt.NCryptSignHash() failed with status code:{0}", num));
            }
            return array;
        }

        public static bool Verify(byte[] securedInput, byte[] signature, CngKey key, CngAlgorithm hash, int saltSize)
        {
            bool flag;
            using (HashAlgorithm hashAlgorithm = RsaPss.HashAlgorithm(hash))
            {
                flag = RsaPss.VerifyHash(hashAlgorithm.ComputeHash(securedInput), signature, key, hash.Algorithm, saltSize);
            }
            return flag;
        }

        private static bool VerifyHash(byte[] hash, byte[] signature, CngKey key, string algorithm, int saltSize)
        {
            BCrypt.BCRYPT_PSS_PADDING_INFO bCRYPTPSSPADDINGINFO = new BCrypt.BCRYPT_PSS_PADDING_INFO(algorithm, saltSize);
            uint num = NCrypt.NCryptVerifySignature(key.Handle, ref bCRYPTPSSPADDINGINFO, hash, (int)hash.Length, signature, (int)signature.Length, 8);
            if (num == -2146893818)
            {
                return false;
            }
            if (num != 0)
            {
                throw new CryptographicException(string.Format("NCrypt.NCryptSignHash() (signature size) failed with status code:{0}", num));
            }
            return true;
        }
    }
}