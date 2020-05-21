using Jose.jwe;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Jose
{
	public class AesCbcHmacEncryption : IJweAlgorithm
	{
		private IJwsAlgorithm hashAlgorithm;

		private readonly int keyLength;

		public int KeySize
		{
			get
			{
				return this.keyLength;
			}
		}

		public AesCbcHmacEncryption(IJwsAlgorithm hashAlgorithm, int keyLength)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.keyLength = keyLength;
		}

		private byte[] ComputeAuthTag(byte[] aad, byte[] iv, byte[] cipherText, byte[] hmacKey)
		{
			byte[] bytes = Arrays.LongToBytes((long)((int)aad.Length * 8));
			byte[] numArray = Arrays.Concat(new byte[][] { aad, iv, cipherText, bytes });
			return Arrays.FirstHalf(this.hashAlgorithm.Sign(numArray, hmacKey));
		}

		public byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
		{
			byte[] array;
			Ensure.BitSize(cek, this.keyLength, string.Format("AES-CBC with HMAC algorithm expected key of size {0} bits, but was given {1} bits", this.keyLength, (int)cek.Length * 8), new object[0]);
			byte[] numArray = Arrays.FirstHalf(cek);
			byte[] numArray1 = Arrays.SecondHalf(cek);
			if (!Arrays.ConstantTimeEquals(this.ComputeAuthTag(aad, iv, cipherText, numArray), authTag))
			{
				throw new IntegrityException("Authentication tag do not match.");
			}
			try
			{
				using (Aes ae = Aes.Create())
				{
					ae.Key = numArray1;
					ae.IV = iv;
					using (MemoryStream memoryStream = new MemoryStream())
					{
						using (ICryptoTransform cryptoTransform = ae.CreateDecryptor(ae.Key, ae.IV))
						{
							using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
							{
								cryptoStream.Write(cipherText, 0, (int)cipherText.Length);
								cryptoStream.FlushFinalBlock();
								array = memoryStream.ToArray();
							}
						}
					}
				}
			}
			catch (CryptographicException cryptographicException)
			{
				throw new EncryptionException("Unable to decrypt content", cryptographicException);
			}
			return array;
		}

		public byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
		{
			byte[] array;
			Ensure.BitSize(cek, this.keyLength, string.Format("AES-CBC with HMAC algorithm expected key of size {0} bits, but was given {1} bits", this.keyLength, (int)cek.Length * 8), new object[0]);
			byte[] numArray = Arrays.FirstHalf(cek);
			byte[] numArray1 = Arrays.SecondHalf(cek);
			byte[] numArray2 = Arrays.Random(128);
			try
			{
				using (Aes ae = Aes.Create())
				{
					ae.Key = numArray1;
					ae.IV = numArray2;
					using (MemoryStream memoryStream = new MemoryStream())
					{
						using (ICryptoTransform cryptoTransform = ae.CreateEncryptor(ae.Key, ae.IV))
						{
							using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
							{
								cryptoStream.Write(plainText, 0, (int)plainText.Length);
								cryptoStream.FlushFinalBlock();
								array = memoryStream.ToArray();
							}
						}
					}
				}
			}
			catch (CryptographicException cryptographicException)
			{
				throw new EncryptionException("Unable to encrypt content.", cryptographicException);
			}
			byte[] numArray3 = this.ComputeAuthTag(aad, numArray2, array, numArray);
			return new byte[][] { numArray2, array, numArray3 };
		}
	}
}