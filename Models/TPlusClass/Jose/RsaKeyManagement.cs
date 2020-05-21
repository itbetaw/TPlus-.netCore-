using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Jose
{
	public class RsaKeyManagement : IKeyManagement
	{
		private bool useRsaOaepPadding;

		private bool useSha256;

		public RsaKeyManagement(bool useRsaOaepPadding, bool useSha256 = false)
		{
			this.useRsaOaepPadding = useRsaOaepPadding;
			this.useSha256 = useSha256;
		}

		public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
		{
			RSACryptoServiceProvider rSACryptoServiceProvider = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.", new object[0]);
			if (!this.useSha256)
			{
				return rSACryptoServiceProvider.Decrypt(encryptedCek, this.useRsaOaepPadding);
			}
			return RsaOaep.Decrypt(encryptedCek, RsaKey.New(rSACryptoServiceProvider.ExportParameters(true)), CngAlgorithm.Sha256);
		}

		public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
		{
			byte[] numArray = Arrays.Random(cekSizeBits);
			RSACryptoServiceProvider rSACryptoServiceProvider = Ensure.Type<RSACryptoServiceProvider>(key, "RsaKeyManagement alg expects key to be of RSACryptoServiceProvider type.", new object[0]);
			if (!this.useSha256)
			{
				return new byte[][] { numArray, rSACryptoServiceProvider.Encrypt(numArray, this.useRsaOaepPadding) };
			}
			return new byte[][] { numArray, RsaOaep.Encrypt(numArray, RsaKey.New(rSACryptoServiceProvider.ExportParameters(false)), CngAlgorithm.Sha256) };
		}
	}
}