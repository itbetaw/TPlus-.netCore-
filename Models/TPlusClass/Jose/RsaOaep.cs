using Jose.native;
using System;
using System.Security.Cryptography;

namespace Jose
{
	public static class RsaOaep
	{
		public static byte[] Decrypt(byte[] cipherText, CngKey key, CngAlgorithm hash)
		{
			uint num;
			BCrypt.BCRYPT_OAEP_PADDING_INFO bCRYPTOAEPPADDINGINFO = new BCrypt.BCRYPT_OAEP_PADDING_INFO(hash.Algorithm);
			uint num1 = NCrypt.NCryptDecrypt(key.Handle, cipherText, (int)cipherText.Length, ref bCRYPTOAEPPADDINGINFO, null, 0, out num, 4);
			if (num1 != 0)
			{
				throw new CryptographicException(string.Format("NCrypt.Decrypt() (plaintext buffer size) failed with status code:{0}", num1));
			}
			byte[] numArray = new byte[num];
			num1 = NCrypt.NCryptDecrypt(key.Handle, cipherText, (int)cipherText.Length, ref bCRYPTOAEPPADDINGINFO, numArray, num, out num, 4);
			if (num1 != 0)
			{
				throw new CryptographicException(string.Format("NCrypt.Decrypt() failed with status code:{0}", num1));
			}
			return numArray;
		}

		public static byte[] Encrypt(byte[] plainText, CngKey key, CngAlgorithm hash)
		{
			uint num;
			BCrypt.BCRYPT_OAEP_PADDING_INFO bCRYPTOAEPPADDINGINFO = new BCrypt.BCRYPT_OAEP_PADDING_INFO(hash.Algorithm);
			uint num1 = NCrypt.NCryptEncrypt(key.Handle, plainText, (int)plainText.Length, ref bCRYPTOAEPPADDINGINFO, null, 0, out num, 4);
			if (num1 != 0)
			{
				throw new CryptographicException(string.Format("NCrypt.Encrypt() (ciphertext buffer size) failed with status code:{0}", num1));
			}
			byte[] numArray = new byte[num];
			num1 = NCrypt.NCryptEncrypt(key.Handle, plainText, (int)plainText.Length, ref bCRYPTOAEPPADDINGINFO, numArray, num, out num, 4);
			if (num1 != 0)
			{
				throw new CryptographicException(string.Format("NCrypt.Encrypt() failed with status code:{0}", num1));
			}
			return numArray;
		}
	}
}