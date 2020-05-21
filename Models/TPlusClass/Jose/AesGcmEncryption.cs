using Jose.jwe;
using System;
using System.Security.Cryptography;

namespace Jose
{
	public class AesGcmEncryption : IJweAlgorithm
	{
		private int keyLength;

		public int KeySize
		{
			get
			{
				return this.keyLength;
			}
		}

		public AesGcmEncryption(int keyLength)
		{
			this.keyLength = keyLength;
		}

		public byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag)
		{
			byte[] numArray;
			Ensure.BitSize(cek, this.keyLength, string.Format("AES-GCM algorithm expected key of size {0} bits, but was given {1} bits", this.keyLength, (int)cek.Length * 8), new object[0]);
			try
			{
				numArray = AesGcm.Decrypt(cek, iv, aad, cipherText, authTag);
			}
			catch (CryptographicException cryptographicException)
			{
				throw new EncryptionException("Unable to decrypt content or authentication tag do not match.", cryptographicException);
			}
			return numArray;
		}

		public byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek)
		{
			byte[][] numArray;
			Ensure.BitSize(cek, this.keyLength, string.Format("AES-GCM algorithm expected key of size {0} bits, but was given {1} bits", this.keyLength, (int)cek.Length * 8), new object[0]);
			byte[] numArray1 = Arrays.Random(96);
			try
			{
				byte[][] numArray2 = AesGcm.Encrypt(cek, numArray1, aad, plainText);
				numArray = new byte[][] { numArray1, numArray2[0], numArray2[1] };
			}
			catch (CryptographicException cryptographicException)
			{
				throw new EncryptionException("Unable to encrypt content.", cryptographicException);
			}
			return numArray;
		}
	}
}