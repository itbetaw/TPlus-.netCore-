using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Jose.native
{
	public static class NCrypt
	{
		public const uint NTE_BAD_SIGNATURE = 2148073478;

		public const uint KDF_ALGORITHMID = 8;

		public const uint KDF_PARTYUINFO = 9;

		public const uint KDF_PARTYVINFO = 10;

		public const uint KDF_SUPPPUBINFO = 11;

		public const uint KDF_SUPPPRIVINFO = 12;

		[DllImport("ncrypt.dll", CharSet=CharSet.None, ExactSpelling=false)]
		internal static extern uint NCryptDecrypt(SafeNCryptKeyHandle hKey, byte[] pbInput, int cbInput, ref BCrypt.BCRYPT_OAEP_PADDING_INFO pvPadding, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

		[DllImport("ncrypt.dll", CharSet=CharSet.Auto, ExactSpelling=false, SetLastError=true)]
		public static extern uint NCryptDeriveKey(SafeNCryptSecretHandle hSharedSecret, string kdf, NCrypt.NCryptBufferDesc parameterList, byte[] derivedKey, uint derivedKeyByteSize, out uint result, uint flags);

		[DllImport("ncrypt.dll", CharSet=CharSet.None, ExactSpelling=false)]
		internal static extern uint NCryptEncrypt(SafeNCryptKeyHandle hKey, byte[] pbInput, int cbInput, ref BCrypt.BCRYPT_OAEP_PADDING_INFO pvPadding, byte[] pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

		[DllImport("ncrypt.dll", CharSet=CharSet.Auto, ExactSpelling=false, SetLastError=true)]
		public static extern uint NCryptSecretAgreement(SafeNCryptKeyHandle hPrivKey, SafeNCryptKeyHandle hPublicKey, out SafeNCryptSecretHandle phSecret, uint flags);

		[DllImport("ncrypt.dll", CharSet=CharSet.None, ExactSpelling=false)]
		internal static extern uint NCryptSignHash(SafeNCryptKeyHandle hKey, ref BCrypt.BCRYPT_PSS_PADDING_INFO pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, int cbSignature, out uint pcbResult, uint dwFlags);

		[DllImport("ncrypt.dll", CharSet=CharSet.None, ExactSpelling=false)]
		internal static extern uint NCryptVerifySignature(SafeNCryptKeyHandle hKey, ref BCrypt.BCRYPT_PSS_PADDING_INFO pPaddingInfo, byte[] pbHashValue, int cbHashValue, byte[] pbSignature, int cbSignature, uint dwFlags);

		public class NCryptBuffer : IDisposable
		{
			public uint cbBuffer;

			public uint BufferType;

			public IntPtr pvBuffer;

			public NCryptBuffer(uint bufferType, string data)
			{
				this.BufferType = bufferType;
				this.cbBuffer = (uint)(data.Length * 2 + 2);
				this.pvBuffer = Marshal.AllocHGlobal(data.Length * 2);
				Marshal.Copy(data.ToCharArray(), 0, this.pvBuffer, data.Length);
			}

			public NCryptBuffer(uint bufferType, byte[] data)
			{
				this.BufferType = bufferType;
				this.cbBuffer = (uint)data.Length;
				this.pvBuffer = Marshal.AllocHGlobal((int)data.Length);
				Marshal.Copy(data, 0, this.pvBuffer, (int)data.Length);
			}

			public void Dispose()
			{
				Marshal.FreeHGlobal(this.pvBuffer);
			}
		}

		public class NCryptBufferDesc : IDisposable
		{
			public uint ulVersion;

			public uint cBuffers;

			public IntPtr pBuffers;

			public NCryptBufferDesc(params NCrypt.NCryptBuffer[] buffers)
			{
				this.cBuffers = (uint)buffers.Length;
				this.ulVersion = 0;
				this.pBuffers = Marshal.AllocHGlobal(((IEnumerable<NCrypt.NCryptBuffer>)buffers).Sum<NCrypt.NCryptBuffer>((NCrypt.NCryptBuffer buf) => Marshal.SizeOf(buf)));
				int num = 0;
				NCrypt.NCryptBuffer[] nCryptBufferArray = buffers;
				for (int i = 0; i < (int)nCryptBufferArray.Length; i++)
				{
					NCrypt.NCryptBuffer nCryptBuffer = nCryptBufferArray[i];
					Marshal.StructureToPtr(nCryptBuffer, this.pBuffers + num, false);
					num += Marshal.SizeOf(nCryptBuffer);
				}
			}

			public void Dispose()
			{
				Marshal.FreeHGlobal(this.pBuffers);
			}
		}
	}
}