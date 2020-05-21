using Jose;
using System;
using System.Security.Cryptography;

namespace Security.Cryptography
{
	public class RsaKey
	{
		public readonly static byte[] BCRYPT_RSAPUBLIC_MAGIC;

		public readonly static byte[] BCRYPT_RSAPRIVATE_MAGIC;

		static RsaKey()
		{
			RsaKey.BCRYPT_RSAPUBLIC_MAGIC = BitConverter.GetBytes(826364754);
			RsaKey.BCRYPT_RSAPRIVATE_MAGIC = BitConverter.GetBytes(843141970);
		}

		public RsaKey()
		{
		}

		public static CngKey New(RSAParameters parameters)
		{
			return RsaKey.New(parameters.Exponent, parameters.Modulus, parameters.P, parameters.Q);
		}

		public static CngKey New(byte[] exponent, byte[] modulus, byte[] p = null, byte[] q = null)
		{
			bool flag = (p == null ? true : q == null);
			byte[] numArray = (flag ? RsaKey.BCRYPT_RSAPUBLIC_MAGIC : RsaKey.BCRYPT_RSAPRIVATE_MAGIC);
			byte[] bytes = BitConverter.GetBytes((int)modulus.Length * 8);
			byte[] bytes1 = BitConverter.GetBytes((int)exponent.Length);
			byte[] numArray1 = BitConverter.GetBytes((int)modulus.Length);
			byte[] numArray2 = (flag ? BitConverter.GetBytes(0) : BitConverter.GetBytes((int)p.Length));
			byte[] numArray3 = (flag ? BitConverter.GetBytes(0) : BitConverter.GetBytes((int)q.Length));
			return CngKey.Import(Arrays.Concat(new byte[][] { numArray, bytes, bytes1, numArray1, numArray2, numArray3, exponent, modulus, p, q }), (flag ? CngKeyBlobFormat.GenericPublicBlob : CngKeyBlobFormat.GenericPrivateBlob));
		}
	}
}