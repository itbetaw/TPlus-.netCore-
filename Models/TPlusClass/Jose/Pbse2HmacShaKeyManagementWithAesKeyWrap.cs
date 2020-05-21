using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Jose
{
	public class Pbse2HmacShaKeyManagementWithAesKeyWrap : IKeyManagement
	{
		private AesKeyWrapManagement aesKW;

		private int keyLengthBits;

		private HMAC PRF
		{
			get
			{
				if (this.keyLengthBits == 128)
				{
					return new HMACSHA256();
				}
				if (this.keyLengthBits == 192)
				{
					return new HMACSHA384();
				}
				if (this.keyLengthBits != 256)
				{
					throw new ArgumentException(string.Format("Unsupported key size: '{0}'", this.keyLengthBits));
				}
				return new HMACSHA512();
			}
		}

		public Pbse2HmacShaKeyManagementWithAesKeyWrap(int keyLengthBits, AesKeyWrapManagement aesKw)
		{
			this.aesKW = aesKw;
			this.keyLengthBits = keyLengthBits;
		}

		public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
		{
			byte[] numArray;
			string str = Ensure.Type<string>(key, "Pbse2HmacShaKeyManagementWithAesKeyWrap management algorithm expectes key to be string.", new object[0]);
			byte[] bytes = Encoding.UTF8.GetBytes(str);
			Ensure.Contains(header, new string[] { "p2c" }, "Pbse2HmacShaKeyManagementWithAesKeyWrap algorithm expects 'p2c' param in JWT header, but was not found", new object[0]);
			Ensure.Contains(header, new string[] { "p2s" }, "Pbse2HmacShaKeyManagementWithAesKeyWrap algorithm expects 'p2s' param in JWT header, but was not found", new object[0]);
			byte[] bytes1 = Encoding.UTF8.GetBytes((string)header["alg"]);
			int num = Convert.ToInt32(header["p2c"]);
			byte[] numArray1 = Base64Url.Decode((string)header["p2s"]);
			byte[] numArray2 = Arrays.Concat(new byte[][] { bytes1, Arrays.Zero, numArray1 });
			using (HMAC pRF = this.PRF)
			{
				numArray = PBKDF2.DeriveKey(bytes, numArray2, num, this.keyLengthBits, pRF);
			}
			return this.aesKW.Unwrap(encryptedCek, numArray, cekSizeBits, header);
		}

		public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
		{
			byte[] numArray;
			string str = Ensure.Type<string>(key, "Pbse2HmacShaKeyManagementWithAesKeyWrap management algorithm expectes key to be string.", new object[0]);
			byte[] bytes = Encoding.UTF8.GetBytes(str);
			byte[] bytes1 = Encoding.UTF8.GetBytes((string)header["alg"]);
			int num = 8192;
			byte[] numArray1 = Arrays.Random(96);
			header["p2c"] = num;
			header["p2s"] = Base64Url.Encode(numArray1);
			byte[] numArray2 = Arrays.Concat(new byte[][] { bytes1, Arrays.Zero, numArray1 });
			using (HMAC pRF = this.PRF)
			{
				numArray = PBKDF2.DeriveKey(bytes, numArray2, num, this.keyLengthBits, pRF);
			}
			return this.aesKW.WrapNewKey(cekSizeBits, numArray, header);
		}
	}
}