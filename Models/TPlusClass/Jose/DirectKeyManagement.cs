using System;
using System.Collections.Generic;

namespace Jose
{
	public class DirectKeyManagement : IKeyManagement
	{
		public DirectKeyManagement()
		{
		}

		public byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
		{
			Ensure.IsEmpty(encryptedCek, "DirectKeyManagement expects empty content encryption key.", new object[0]);
			return Ensure.Type<byte[]>(key, "DirectKeyManagement alg expectes key to be byte[] array.", new object[0]);
		}

		public byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
		{
			return new byte[][] { Ensure.Type<byte[]>(key, "DirectKeyManagement alg expectes key to be byte[] array.", new object[0]), Arrays.Empty };
		}
	}
}