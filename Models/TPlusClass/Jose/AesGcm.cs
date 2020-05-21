using Jose.native;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Jose
{
	public static class AesGcm
	{
		public static byte[] Decrypt(byte[] key, byte[] iv, byte[] aad, byte[] cipherText, byte[] authTag)
		{
			IntPtr intPtr;
			byte[] numArray;
			IntPtr intPtr1 = AesGcm.OpenAlgorithmProvider(BCrypt.BCRYPT_AES_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER, BCrypt.BCRYPT_CHAIN_MODE_GCM);
			IntPtr intPtr2 = AesGcm.ImportKey(intPtr1, key, out intPtr);
			BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bCRYPTAUTHENTICATEDCIPHERMODEINFO = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, authTag);
			BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bCRYPTAUTHENTICATEDCIPHERMODEINFO1 = bCRYPTAUTHENTICATEDCIPHERMODEINFO;
			try
			{
				byte[] numArray1 = new byte[AesGcm.MaxAuthTagSize(intPtr1)];
				int num = 0;
				uint num1 = BCrypt.BCryptDecrypt(intPtr, cipherText, (int)cipherText.Length, ref bCRYPTAUTHENTICATEDCIPHERMODEINFO, numArray1, (int)numArray1.Length, null, 0, ref num, 0);
				if (num1 != 0)
				{
					throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() (get size) failed with status code: {0}", num1));
				}
				numArray = new byte[num];
				num1 = BCrypt.BCryptDecrypt(intPtr, cipherText, (int)cipherText.Length, ref bCRYPTAUTHENTICATEDCIPHERMODEINFO, numArray1, (int)numArray1.Length, numArray, (int)numArray.Length, ref num, 0);
				if (num1 == BCrypt.STATUS_AUTH_TAG_MISMATCH)
				{
					throw new CryptographicException("BCrypt.BCryptDecrypt(): authentication tag mismatch");
				}
				if (num1 != 0)
				{
					throw new CryptographicException(string.Format("BCrypt.BCryptDecrypt() failed with status code:{0}", num1));
				}
			}
			finally
			{
				((IDisposable)bCRYPTAUTHENTICATEDCIPHERMODEINFO1).Dispose();
			}
			BCrypt.BCryptDestroyKey(intPtr);
			Marshal.FreeHGlobal(intPtr2);
			BCrypt.BCryptCloseAlgorithmProvider(intPtr1, 0);
			return numArray;
		}

		public static byte[][] Encrypt(byte[] key, byte[] iv, byte[] aad, byte[] plainText)
		{
			IntPtr intPtr;
			byte[] numArray;
			IntPtr intPtr1 = AesGcm.OpenAlgorithmProvider(BCrypt.BCRYPT_AES_ALGORITHM, BCrypt.MS_PRIMITIVE_PROVIDER, BCrypt.BCRYPT_CHAIN_MODE_GCM);
			IntPtr intPtr2 = AesGcm.ImportKey(intPtr1, key, out intPtr);
			byte[] numArray1 = new byte[AesGcm.MaxAuthTagSize(intPtr1)];
			BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bCRYPTAUTHENTICATEDCIPHERMODEINFO = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(iv, aad, numArray1);
			BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO bCRYPTAUTHENTICATEDCIPHERMODEINFO1 = bCRYPTAUTHENTICATEDCIPHERMODEINFO;
			try
			{
				byte[] numArray2 = new byte[(int)numArray1.Length];
				int num = 0;
				uint num1 = BCrypt.BCryptEncrypt(intPtr, plainText, (int)plainText.Length, ref bCRYPTAUTHENTICATEDCIPHERMODEINFO, numArray2, (int)numArray2.Length, null, 0, ref num, 0);
				if (num1 != 0)
				{
					throw new CryptographicException(string.Format("BCrypt.BCryptEncrypt() (get size) failed with status code:{0}", num1));
				}
				numArray = new byte[num];
				num1 = BCrypt.BCryptEncrypt(intPtr, plainText, (int)plainText.Length, ref bCRYPTAUTHENTICATEDCIPHERMODEINFO, numArray2, (int)numArray2.Length, numArray, (int)numArray.Length, ref num, 0);
				if (num1 != 0)
				{
					throw new CryptographicException(string.Format("BCrypt.BCryptEncrypt() failed with status code:{0}", num1));
				}
				Marshal.Copy(bCRYPTAUTHENTICATEDCIPHERMODEINFO.pbTag, numArray1, 0, bCRYPTAUTHENTICATEDCIPHERMODEINFO.cbTag);
			}
			finally
			{
				((IDisposable)bCRYPTAUTHENTICATEDCIPHERMODEINFO1).Dispose();
			}
			BCrypt.BCryptDestroyKey(intPtr);
			Marshal.FreeHGlobal(intPtr2);
			BCrypt.BCryptCloseAlgorithmProvider(intPtr1, 0);
			return new byte[][] { numArray, numArray1 };
		}

		private static byte[] GetProperty(IntPtr hAlg, string name)
		{
			int num = 0;
			uint num1 = BCrypt.BCryptGetProperty(hAlg, name, null, 0, ref num, 0);
			if (num1 != 0)
			{
				throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() (get size) failed with status code:{0}", num1));
			}
			byte[] numArray = new byte[num];
			num1 = BCrypt.BCryptGetProperty(hAlg, name, numArray, (int)numArray.Length, ref num, 0);
			if (num1 != 0)
			{
				throw new CryptographicException(string.Format("BCrypt.BCryptGetProperty() failed with status code:{0}", num1));
			}
			return numArray;
		}

		private static IntPtr ImportKey(IntPtr hAlg, byte[] key, out IntPtr hKey)
		{
			int num = BitConverter.ToInt32(AesGcm.GetProperty(hAlg, BCrypt.BCRYPT_OBJECT_LENGTH), 0);
			IntPtr intPtr = Marshal.AllocHGlobal(num);
			byte[] numArray = Arrays.Concat(new byte[][] { BCrypt.BCRYPT_KEY_DATA_BLOB_MAGIC, BitConverter.GetBytes(1), BitConverter.GetBytes((int)key.Length), key });
			uint num1 = BCrypt.BCryptImportKey(hAlg, IntPtr.Zero, BCrypt.BCRYPT_KEY_DATA_BLOB, out hKey, intPtr, num, numArray, (int)numArray.Length, 0);
			if (num1 != 0)
			{
				throw new CryptographicException(string.Format("BCrypt.BCryptImportKey() failed with status code:{0}", num1));
			}
			return intPtr;
		}

		private static int MaxAuthTagSize(IntPtr hAlg)
		{
			byte[] property = AesGcm.GetProperty(hAlg, BCrypt.BCRYPT_AUTH_TAG_LENGTH);
			return BitConverter.ToInt32(new byte[] { property[4], property[5], property[6], property[7] }, 0);
		}

		private static IntPtr OpenAlgorithmProvider(string alg, string provider, string chainingMode)
		{
			IntPtr zero = IntPtr.Zero;
			uint num = BCrypt.BCryptOpenAlgorithmProvider(out zero, alg, provider, 0);
			if (num != 0)
			{
				throw new CryptographicException(string.Format("BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}", num));
			}
			byte[] bytes = Encoding.Unicode.GetBytes(chainingMode);
			num = BCrypt.BCryptSetAlgorithmProperty(zero, BCrypt.BCRYPT_CHAINING_MODE, bytes, (int)bytes.Length, 0);
			if (num != 0)
			{
				throw new CryptographicException(string.Format("BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed with status code:{0}", num));
			}
			return zero;
		}
	}
}