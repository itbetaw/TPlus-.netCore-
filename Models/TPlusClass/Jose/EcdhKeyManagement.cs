using Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Jose
{
	public class EcdhKeyManagement : IKeyManagement
	{
		private string algIdHeader;

		public EcdhKeyManagement(bool isDirectAgreement)
		{
			this.algIdHeader = (isDirectAgreement ? "enc" : "alg");
		}

		private string Curve(CngKey key)
		{
			if (key.Algorithm == CngAlgorithm.ECDiffieHellmanP256)
			{
				return "P-256";
			}
			if (key.Algorithm == CngAlgorithm.ECDiffieHellmanP384)
			{
				return "P-384";
			}
			if (key.Algorithm != CngAlgorithm.ECDiffieHellmanP521)
			{
				throw new ArgumentException(string.Concat("Unknown curve type ", key.Algorithm));
			}
			return "P-521";
		}

		private byte[] DeriveKey(IDictionary<string, object> header, int cekSizeBits, CngKey externalPublicKey, CngKey privateKey)
		{
			byte[] bytes = Encoding.UTF8.GetBytes((string)header[this.algIdHeader]);
			byte[] numArray = (header.ContainsKey("apv") ? Base64Url.Decode((string)header["apv"]) : Arrays.Empty);
			byte[] numArray1 = (header.ContainsKey("apu") ? Base64Url.Decode((string)header["apu"]) : Arrays.Empty);
			byte[] numArray2 = Arrays.Concat(new byte[][] { Arrays.IntToBytes((int)bytes.Length), bytes });
			byte[] numArray3 = Arrays.Concat(new byte[][] { Arrays.IntToBytes((int)numArray1.Length), numArray1 });
			byte[] numArray4 = Arrays.Concat(new byte[][] { Arrays.IntToBytes((int)numArray.Length), numArray });
			byte[] bytes1 = Arrays.IntToBytes(cekSizeBits);
			return ConcatKDF.DeriveKey(externalPublicKey, privateKey, cekSizeBits, numArray2, numArray4, numArray3, bytes1);
		}

		private byte[] NewKey(int keyLength, object key, IDictionary<string, object> header)
		{
			CngKey cngKey = Ensure.Type<CngKey>(key, "EcdhKeyManagement alg expects key to be of CngKey type.", new object[0]);
			EccKey eccKey = EccKey.Generate(cngKey);
			IDictionary<string, object> strs = new Dictionary<string, object>();
			strs["kty"] = "EC";
			strs["x"] = Base64Url.Encode(eccKey.X);
			strs["y"] = Base64Url.Encode(eccKey.Y);
			strs["crv"] = this.Curve(cngKey);
			header["epk"] = strs;
			return this.DeriveKey(header, keyLength, cngKey, eccKey.Key);
		}

		public virtual byte[] Unwrap(byte[] encryptedCek, object key, int cekSizeBits, IDictionary<string, object> header)
		{
			CngKey cngKey = Ensure.Type<CngKey>(key, "EcdhKeyManagement alg expects key to be of CngKey type.", new object[0]);
			Ensure.Contains(header, new string[] { "epk" }, "EcdhKeyManagement algorithm expects 'epk' key param in JWT header, but was not found", new object[0]);
			Ensure.Contains(header, new string[] { this.algIdHeader }, "EcdhKeyManagement algorithm expects 'enc' header to be present in JWT header, but was not found", new object[0]);
			IDictionary<string, object> item = (IDictionary<string, object>)header["epk"];
			Ensure.Contains(item, new string[] { "x", "y", "crv" }, "EcdhKeyManagement algorithm expects 'epk' key to contain 'x','y' and 'crv' fields.", new object[0]);
			byte[] numArray = Base64Url.Decode((string)item["x"]);
			byte[] numArray1 = Base64Url.Decode((string)item["y"]);
			CngKey cngKey1 = EccKey.New(numArray, numArray1, null, CngKeyUsages.KeyAgreement);
			return this.DeriveKey(header, cekSizeBits, cngKey1, cngKey);
		}

		public virtual byte[] Wrap(byte[] cek, object key)
		{
			return Arrays.Empty;
		}

		public virtual byte[][] WrapNewKey(int cekSizeBits, object key, IDictionary<string, object> header)
		{
			byte[] numArray = this.NewKey(cekSizeBits, key, header);
			byte[] numArray1 = this.Wrap(numArray, key);
			return new byte[][] { numArray, numArray1 };
		}
	}
}