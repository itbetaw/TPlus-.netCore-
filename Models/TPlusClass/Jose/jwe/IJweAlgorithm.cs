using System;

namespace Jose.jwe
{
	public interface IJweAlgorithm
	{
		int KeySize
		{
			get;
		}

		byte[] Decrypt(byte[] aad, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag);

		byte[][] Encrypt(byte[] aad, byte[] plainText, byte[] cek);
	}
}