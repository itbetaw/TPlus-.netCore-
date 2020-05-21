using Security.Cryptography;
using System;
using System.Security.Cryptography;

namespace Jose
{
	public class RsaPssUsingSha : IJwsAlgorithm
	{
		private int saltSize;

		private CngAlgorithm Hash
		{
			get
			{
				if (this.saltSize == 32)
				{
					return CngAlgorithm.Sha256;
				}
				if (this.saltSize == 48)
				{
					return CngAlgorithm.Sha384;
				}
				if (this.saltSize != 64)
				{
					throw new ArgumentException(string.Format("Unsupported salt size: '{0} bytes'", this.saltSize));
				}
				return CngAlgorithm.Sha512;
			}
		}

		public RsaPssUsingSha(int saltSize)
		{
			this.saltSize = saltSize;
		}

		public byte[] Sign(byte[] securedInput, object key)
		{
			byte[] numArray;
			RSACryptoServiceProvider rSACryptoServiceProvider = Ensure.Type<RSACryptoServiceProvider>(key, "RsaUsingSha with PSS padding alg expects key to be of RSACryptoServiceProvider type.", new object[0]);
			try
			{
				numArray = RsaPss.Sign(securedInput, RsaKey.New(rSACryptoServiceProvider.ExportParameters(true)), this.Hash, this.saltSize);
			}
			catch (CryptographicException cryptographicException)
			{
				throw new JoseException("Unable to sign content.", cryptographicException);
			}
			return numArray;
		}

		public bool Verify(byte[] signature, byte[] securedInput, object key)
		{
			bool flag;
			RSACryptoServiceProvider rSACryptoServiceProvider = Ensure.Type<RSACryptoServiceProvider>(key, "RsaUsingSha with PSS padding alg expects key to be of RSACryptoServiceProvider type.", new object[0]);
			try
			{
				flag = RsaPss.Verify(securedInput, signature, RsaKey.New(rSACryptoServiceProvider.ExportParameters(false)), this.Hash, this.saltSize);
			}
			catch (CryptographicException cryptographicException)
			{
				flag = false;
			}
			return flag;
		}
	}
}