using System;
using System.Collections.Generic;

namespace Jose
{
	public class EcdhKeyManagementWithAesKeyWrap : EcdhKeyManagement
	{
		private AesKeyWrapManagement aesKW;

		private int keyLengthBits;

		public EcdhKeyManagementWithAesKeyWrap(int keyLengthBits, AesKeyWrapManagement aesKw) : base(false)
		{
			this.aesKW = aesKw;
			this.keyLengthBits = keyLengthBits;
		}

		public override byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
		{
			byte[] numArray = base.Unwrap(Arrays.Empty, key, this.keyLengthBits, header);
			return this.aesKW.Unwrap(encryptedCek, numArray, cekSizeBits, header);
		}

		public override byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
		{
			byte[] numArray = base.WrapNewKey(this.keyLengthBits, key, header)[0];
			return this.aesKW.WrapNewKey(cekSizeBits, numArray, header);
		}
	}
}