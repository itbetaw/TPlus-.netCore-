using System;
using System.Collections.Generic;

namespace Jose
{
	public class AesGcmKeyWrapManagement : IKeyManagement
	{
		private int keyLengthBits;

		public AesGcmKeyWrapManagement(int keyLengthBits)
		{
			this.keyLengthBits = keyLengthBits;
		}

		public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
		{
			byte[] numArray = Ensure.Type<byte[]>(key, "AesGcmKeyWrapManagement alg expectes key to be byte[] array.", new object[0]);
			Ensure.BitSize(numArray, this.keyLengthBits, string.Format("AesGcmKeyWrapManagement management algorithm expected key of size {0} bits, but was given {1} bits", this.keyLengthBits, (int)numArray.Length * 8), new object[0]);
			Ensure.Contains(header, new string[] { "iv" }, "AesGcmKeyWrapManagement algorithm expects 'iv' param in JWT header, but was not found", new object[0]);
			Ensure.Contains(header, new string[] { "tag" }, "AesGcmKeyWrapManagement algorithm expects 'tag' param in JWT header, but was not found", new object[0]);
			byte[] numArray1 = Base64Url.Decode((string)header["iv"]);
			byte[] numArray2 = Base64Url.Decode((string)header["tag"]);
			return AesGcm.Decrypt(numArray, numArray1, null, encryptedCek, numArray2);
		}

		public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
		{
			byte[] numArray = Ensure.Type<byte[]>(key, "AesGcmKeyWrapManagement alg expectes key to be byte[] array.", new object[0]);
			Ensure.BitSize(numArray, this.keyLengthBits, string.Format("AesGcmKeyWrapManagement management algorithm expected key of size {0} bits, but was given {1} bits", this.keyLengthBits, (int)numArray.Length * 8), new object[0]);
			byte[] numArray1 = Arrays.Random(96);
			byte[] numArray2 = Arrays.Random(cekSizeBits);
			byte[][] numArray3 = AesGcm.Encrypt(numArray, numArray1, null, numArray2);
			header["iv"] = Base64Url.Encode(numArray1);
			header["tag"] = Base64Url.Encode(numArray3[1]);
			return new byte[][] { numArray2, numArray3[0] };
		}
	}
}