using System;
using System.Collections.Generic;

namespace Jose
{
	public interface IKeyManagement
	{
		byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header);

		byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header);
	}
}