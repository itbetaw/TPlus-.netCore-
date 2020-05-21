using System;
using System.IO;
using System.IO.Compression;

namespace Jose
{
	public class DeflateCompression : ICompression
	{
		public DeflateCompression()
		{
		}

		public byte[] Compress(byte[] plainText)
		{
			byte[] array;
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
				{
					deflateStream.Write(plainText, 0, (int)plainText.Length);
				}
				array = memoryStream.ToArray();
			}
			return array;
		}

		public byte[] Decompress(byte[] compressedText)
		{
			byte[] array;
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (MemoryStream memoryStream1 = new MemoryStream(compressedText))
				{
					using (DeflateStream deflateStream = new DeflateStream(memoryStream1, CompressionMode.Decompress))
					{
						deflateStream.CopyTo(memoryStream);
					}
				}
				array = memoryStream.ToArray();
			}
			return array;
		}
	}
}