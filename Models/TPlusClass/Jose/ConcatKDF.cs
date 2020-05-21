using Jose.native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Security.Cryptography;

namespace Jose
{
	public class ConcatKDF
	{
		public ConcatKDF()
		{
		}

		public static byte[] DeriveKey(CngKey externalPubKey, CngKey privateKey, int keyBitLength, byte[] algorithmId, byte[] partyVInfo, byte[] partyUInfo, byte[] suppPubInfo)
		{
			uint num;
			byte[] numArray;
			using (ECDiffieHellmanCng eCDiffieHellmanCng = new ECDiffieHellmanCng(privateKey))
			{
				using (SafeNCryptSecretHandle safeNCryptSecretHandle = eCDiffieHellmanCng.DeriveSecretAgreementHandle(externalPubKey))
				{
					using (NCrypt.NCryptBuffer nCryptBuffer = new NCrypt.NCryptBuffer(8, algorithmId))
					{
						using (NCrypt.NCryptBuffer nCryptBuffer1 = new NCrypt.NCryptBuffer(10, partyVInfo))
						{
							using (NCrypt.NCryptBuffer nCryptBuffer2 = new NCrypt.NCryptBuffer(9, partyUInfo))
							{
								using (NCrypt.NCryptBuffer nCryptBuffer3 = new NCrypt.NCryptBuffer(11, suppPubInfo))
								{
									using (NCrypt.NCryptBufferDesc nCryptBufferDesc = new NCrypt.NCryptBufferDesc(new NCrypt.NCryptBuffer[] { nCryptBuffer, nCryptBuffer1, nCryptBuffer2, nCryptBuffer3 }))
									{
										uint num1 = NCrypt.NCryptDeriveKey(safeNCryptSecretHandle, "SP800_56A_CONCAT", nCryptBufferDesc, null, 0, out num, 0);
										if (num1 != 0)
										{
											throw new CryptographicException(string.Format("NCrypt.NCryptDeriveKey() failed with status code:{0}", num1));
										}
										byte[] numArray1 = new byte[num];
										num1 = NCrypt.NCryptDeriveKey(safeNCryptSecretHandle, "SP800_56A_CONCAT", nCryptBufferDesc, numArray1, num, out num, 0);
										if (num1 != 0)
										{
											throw new CryptographicException(string.Format("NCrypt.NCryptDeriveKey() failed with status code:{0}", num1));
										}
										numArray = Arrays.LeftmostBits(numArray1, keyBitLength);
									}
								}
							}
						}
					}
				}
			}
			return numArray;
		}
	}
}