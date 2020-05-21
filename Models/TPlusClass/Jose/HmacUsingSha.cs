using System;
using System.Security.Cryptography;

namespace Jose
{
	public class HmacUsingSha : IJwsAlgorithm
	{
		private string hashMethod;

		public HmacUsingSha(string hashMethod)
		{
			this.hashMethod = hashMethod;
		}

		private KeyedHashAlgorithm KeyedHash(byte[] key)
		{
			if ("SHA256".Equals(this.hashMethod))
			{
				return new HMACSHA256(key);
			}
			if ("SHA384".Equals(this.hashMethod))
			{
				return new HMACSHA384(key);
			}
			if (!"SHA512".Equals(this.hashMethod))
			{
				throw new ArgumentException("Unsupported hashing algorithm: '{0}'", this.hashMethod);
			}
			return new HMACSHA512(key);
		}

		public byte[] Sign(byte[] securedInput, object key)
		{
			byte[] numArray;
			byte[] numArray1 = Ensure.Type<byte[]>(key, "HmacUsingSha alg expectes key to be byte[] array.", new object[0]);
			using (KeyedHashAlgorithm keyedHashAlgorithm = this.KeyedHash(numArray1))
			{
				numArray = keyedHashAlgorithm.ComputeHash(securedInput);
			}
			return numArray;
		}

		public bool Verify(byte[] signature, byte[] securedInput, object key)
		{
			return Arrays.ConstantTimeEquals(signature, this.Sign(securedInput, key));
		}
	}
}