using System;
using System.Runtime.InteropServices;

namespace Jose.native
{
    public static class BCrypt
    {
        public const uint ERROR_SUCCESS = 0;

        public const uint BCRYPT_PAD_PSS = 8;

        public const uint BCRYPT_PAD_OAEP = 4;

        public readonly static byte[] BCRYPT_KEY_DATA_BLOB_MAGIC;

        public readonly static string BCRYPT_OBJECT_LENGTH;

        public readonly static string BCRYPT_CHAIN_MODE_GCM;

        public readonly static string BCRYPT_AUTH_TAG_LENGTH;

        public readonly static string BCRYPT_CHAINING_MODE;

        public readonly static string BCRYPT_KEY_DATA_BLOB;

        public readonly static string BCRYPT_AES_ALGORITHM;

        public readonly static string MS_PRIMITIVE_PROVIDER;

        public readonly static int BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

        public readonly static int BCRYPT_INIT_AUTH_MODE_INFO_VERSION;

        public readonly static uint STATUS_AUTH_TAG_MISMATCH;

        static BCrypt()
        {
            BCrypt.BCRYPT_KEY_DATA_BLOB_MAGIC = BitConverter.GetBytes(1296188491);
            BCrypt.BCRYPT_OBJECT_LENGTH = "ObjectLength";
            BCrypt.BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
            BCrypt.BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength";
            BCrypt.BCRYPT_CHAINING_MODE = "ChainingMode";
            BCrypt.BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";
            BCrypt.BCRYPT_AES_ALGORITHM = "AES";
            BCrypt.MS_PRIMITIVE_PROVIDER = "Microsoft Primitive Provider";
            BCrypt.BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 1;
            BCrypt.BCRYPT_INIT_AUTH_MODE_INFO_VERSION = 1;
            BCrypt.STATUS_AUTH_TAG_MISMATCH = unchecked((uint)-1073700862);
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.None, ExactSpelling = false)]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.None, ExactSpelling = false)]
        internal static extern uint BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, ref int pcbResult, int dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.None, ExactSpelling = false)]
        public static extern uint BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll", CharSet = CharSet.None, ExactSpelling = false)]
        public static extern uint BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, ref int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.None, ExactSpelling = false)]
        public static extern uint BCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, ref int pcbResult, uint flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.None, ExactSpelling = false)]
        public static extern uint BCryptImportKey(IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbInput, int cbInput, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.None, ExactSpelling = false)]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.None, EntryPoint = "BCryptSetProperty", ExactSpelling = false)]
        internal static extern uint BCryptSetAlgorithmProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
        {
            public int cbSize;

            public int dwInfoVersion;

            public IntPtr pbNonce;

            public int cbNonce;

            public IntPtr pbAuthData;

            public int cbAuthData;

            public IntPtr pbTag;

            public int cbTag;

            public IntPtr pbMacContext;

            public int cbMacContext;

            public int cbAAD;

            public long cbData;

            public int dwFlags;

            public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(byte[] iv, byte[] aad, byte[] tag)
            {
                this = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
                {
                    dwInfoVersion = BCrypt.BCRYPT_INIT_AUTH_MODE_INFO_VERSION,
                    cbSize = Marshal.SizeOf(typeof(BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO))
                };
                if (iv != null)
                {
                    this.cbNonce = (int)iv.Length;
                    this.pbNonce = Marshal.AllocHGlobal(this.cbNonce);
                    Marshal.Copy(iv, 0, this.pbNonce, this.cbNonce);
                }
                if (aad != null)
                {
                    this.cbAuthData = (int)aad.Length;
                    this.pbAuthData = Marshal.AllocHGlobal(this.cbAuthData);
                    Marshal.Copy(aad, 0, this.pbAuthData, this.cbAuthData);
                }
                if (tag != null)
                {
                    this.cbTag = (int)tag.Length;
                    this.pbTag = Marshal.AllocHGlobal(this.cbTag);
                    Marshal.Copy(tag, 0, this.pbTag, this.cbTag);
                    this.cbMacContext = (int)tag.Length;
                    this.pbMacContext = Marshal.AllocHGlobal(this.cbMacContext);
                }
            }

            public void Dispose()
            {
                if (this.pbNonce != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(this.pbNonce);
                }
                if (this.pbTag != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(this.pbTag);
                }
                if (this.pbAuthData != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(this.pbAuthData);
                }
                if (this.pbMacContext != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(this.pbMacContext);
                }
            }
        }

        public struct BCRYPT_KEY_LENGTHS_STRUCT
        {
            public int dwMinLength;

            public int dwMaxLength;

            public int dwIncrement;
        }

        public struct BCRYPT_OAEP_PADDING_INFO
        {
            public string pszAlgId;

            public IntPtr pbLabel;

            public int cbLabel;

            public BCRYPT_OAEP_PADDING_INFO(string alg)
            {
                this.pszAlgId = alg;
                this.pbLabel = IntPtr.Zero;
                this.cbLabel = 0;
            }
        }

        public struct BCRYPT_PSS_PADDING_INFO
        {
            public string pszAlgId;

            public int cbSalt;

            public BCRYPT_PSS_PADDING_INFO(string pszAlgId, int cbSalt)
            {
                this.pszAlgId = pszAlgId;
                this.cbSalt = cbSalt;
            }
        }
    }
}