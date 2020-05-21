using System;
using System.Security.Cryptography;

namespace Jose
{
	public class EcdsaUsingSha : IJwsAlgorithm
	{
		private int keySize;

		protected CngAlgorithm Hash
		{
			get
			{
				if (this.keySize == 256)
				{
					return CngAlgorithm.Sha256;
				}
				if (this.keySize == 384)
				{
					return CngAlgorithm.Sha384;
				}
				if (this.keySize != 521)
				{
					throw new ArgumentException(string.Format("Unsupported key size: '{0} bytes'", this.keySize));
				}
				return CngAlgorithm.Sha512;
			}
		}

		public EcdsaUsingSha(int keySize)
		{
			this.keySize = keySize;
		}

		public byte[] Sign(byte[] securedInput, object key)
		{
			byte[] numArray;
			CngKey cngKey = Ensure.Type<CngKey>(key, "EcdsaUsingSha alg expects key to be of CngKey type.", new object[0]);
			Ensure.BitSize(cngKey.KeySize, this.keySize, string.Format("ECDSA algorithm expected key of size {0} bits, but was given {1} bits", this.keySize, cngKey.KeySize));
			try
			{
				using (ECDsaCng eCDsaCng = new ECDsaCng(cngKey))
				{
					eCDsaCng.HashAlgorithm = this.Hash;
					numArray = eCDsaCng.SignData(securedInput);
				}
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
			CngKey cngKey = Ensure.Type<CngKey>(key, "EcdsaUsingSha alg expects key to be of CngKey type.", new object[0]);
			Ensure.BitSize(cngKey.KeySize, this.keySize, string.Format("ECDSA algorithm expected key of size {0} bits, but was given {1} bits", this.keySize, cngKey.KeySize));
			try
			{
				using (ECDsaCng eCDsaCng = new ECDsaCng(cngKey))
				{
					eCDsaCng.HashAlgorithm = this.Hash;
					flag = eCDsaCng.VerifyData(securedInput, signature);
				}
			}
			catch (CryptographicException cryptographicException)
			{
				flag = false;
			}
			return flag;
		}
	}
}