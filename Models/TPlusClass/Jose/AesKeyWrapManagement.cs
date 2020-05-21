using System;
using System.Collections.Generic;

namespace Jose
{
	public class AesKeyWrapManagement : IKeyManagement
	{
		private readonly int kekLengthBits;

		public AesKeyWrapManagement(int kekLengthBits)
		{
			this.kekLengthBits = kekLengthBits;
		}

		public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
		{
			byte[] numArray = Ensure.Type<byte[]>(key, "AesKeyWrap management algorithm expectes key to be byte[] array.", new object[0]);
			Ensure.BitSize(numArray, this.kekLengthBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", this.kekLengthBits, (int)numArray.Length * 8), new object[0]);
			return AesKeyWrap.Unwrap(encryptedCek, numArray);
		}

		public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
		{
			byte[] numArray = Ensure.Type<byte[]>(key, "AesKeyWrap management algorithm expectes key to be byte[] array.", new object[0]);
			Ensure.BitSize(numArray, this.kekLengthBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", this.kekLengthBits, (int)numArray.Length * 8), new object[0]);
			byte[] numArray1 = Arrays.Random(cekSizeBits);
			byte[] numArray2 = AesKeyWrap.Wrap(numArray1, numArray);
			return new byte[][] { numArray1, numArray2 };
		}
	}
}