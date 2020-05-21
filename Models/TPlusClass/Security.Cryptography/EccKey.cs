using Jose;
using System;
using System.Security.Cryptography;

namespace Security.Cryptography
{
    public class EccKey
    {
        public readonly static byte[] BCRYPT_ECDSA_PUBLIC_P256_MAGIC;

        public readonly static byte[] BCRYPT_ECDSA_PRIVATE_P256_MAGIC;

        public readonly static byte[] BCRYPT_ECDSA_PUBLIC_P384_MAGIC;

        public readonly static byte[] BCRYPT_ECDSA_PRIVATE_P384_MAGIC;

        public readonly static byte[] BCRYPT_ECDSA_PUBLIC_P521_MAGIC;

        public readonly static byte[] BCRYPT_ECDSA_PRIVATE_P521_MAGIC;

        public readonly static byte[] BCRYPT_ECDH_PUBLIC_P256_MAGIC;

        public readonly static byte[] BCRYPT_ECDH_PRIVATE_P256_MAGIC;

        public readonly static byte[] BCRYPT_ECDH_PUBLIC_P384_MAGIC;

        public readonly static byte[] BCRYPT_ECDH_PRIVATE_P384_MAGIC;

        public readonly static byte[] BCRYPT_ECDH_PUBLIC_P521_MAGIC;

        public readonly static byte[] BCRYPT_ECDH_PRIVATE_P521_MAGIC;

        private CngKey key;

        private byte[] x;

        private byte[] y;

        private byte[] d;

        public byte[] D
        {
            get
            {
                if (this.d == null)
                {
                    this.ExportKey();
                }
                return this.d;
            }
        }

        public CngKey Key
        {
            get
            {
                return this.key;
            }
        }

        public byte[] X
        {
            get
            {
                if (this.x == null)
                {
                    this.ExportKey();
                }
                return this.x;
            }
        }

        public byte[] Y
        {
            get
            {
                if (this.y == null)
                {
                    this.ExportKey();
                }
                return this.y;
            }
        }

        static EccKey()
        {
            EccKey.BCRYPT_ECDSA_PUBLIC_P256_MAGIC = BitConverter.GetBytes(827540293);
            EccKey.BCRYPT_ECDSA_PRIVATE_P256_MAGIC = BitConverter.GetBytes(844317509);
            EccKey.BCRYPT_ECDSA_PUBLIC_P384_MAGIC = BitConverter.GetBytes(861094725);
            EccKey.BCRYPT_ECDSA_PRIVATE_P384_MAGIC = BitConverter.GetBytes(877871941);
            EccKey.BCRYPT_ECDSA_PUBLIC_P521_MAGIC = BitConverter.GetBytes(894649157);
            EccKey.BCRYPT_ECDSA_PRIVATE_P521_MAGIC = BitConverter.GetBytes(911426373);
            EccKey.BCRYPT_ECDH_PUBLIC_P256_MAGIC = BitConverter.GetBytes(827016005);
            EccKey.BCRYPT_ECDH_PRIVATE_P256_MAGIC = BitConverter.GetBytes(843793221);
            EccKey.BCRYPT_ECDH_PUBLIC_P384_MAGIC = BitConverter.GetBytes(860570437);
            EccKey.BCRYPT_ECDH_PRIVATE_P384_MAGIC = BitConverter.GetBytes(877347653);
            EccKey.BCRYPT_ECDH_PUBLIC_P521_MAGIC = BitConverter.GetBytes(894124869);
            EccKey.BCRYPT_ECDH_PRIVATE_P521_MAGIC = BitConverter.GetBytes(910902085);
        }

        public EccKey()
        {
        }

        public static EccKey Export(CngKey _key)
        {
            return new EccKey()
            {
                key = _key
            };
        }

        private void ExportKey()
        {
            byte[] numArray = this.key.Export(CngKeyBlobFormat.EccPrivateBlob);
            int num = BitConverter.ToInt32(new byte[] { numArray[4], numArray[5], numArray[6], numArray[7] }, 0);
            byte[][] numArray1 = Arrays.Slice(Arrays.RightmostBits(numArray, num * 24), num);
            this.x = numArray1[0];
            this.y = numArray1[1];
            this.d = numArray1[2];
        }

        public static EccKey Generate(CngKey recieverPubKey)
        {
            CngKey cngKey = CngKey.Create(recieverPubKey.Algorithm, null, new CngKeyCreationParameters()
            {
                ExportPolicy = new CngExportPolicies?(CngExportPolicies.AllowPlaintextExport)
            });
            return new EccKey()
            {
                key = cngKey
            };
        }

        public static CngKey New(byte[] x, byte[] y, byte[] d = null, CngKeyUsages usage = CngKeyUsages.Signing)
        {
            byte[] numArray;
            CngKeyBlobFormat eccPrivateBlob;
            byte[] numArray1;
            byte[] numArray2;
            byte[] numArray3;
            byte[] numArray4;
            if ((int)x.Length != (int)y.Length)
            {
                throw new ArgumentException("X,Y and D must be same size");
            }
            if (d != null && (int)x.Length != (int)d.Length)
            {
                throw new ArgumentException("X,Y and D must be same size");
            }
            if (usage != CngKeyUsages.Signing && usage != CngKeyUsages.KeyAgreement)
            {
                throw new ArgumentException("Usage parameter expected to be set either 'CngKeyUsages.Signing' or 'CngKeyUsages.KeyAgreement");
            }
            bool flag = usage == CngKeyUsages.Signing;
            int length = (int)x.Length;
            if (length == 32)
            {
                if (d == null)
                {
                    numArray4 = (flag ? EccKey.BCRYPT_ECDSA_PUBLIC_P256_MAGIC : EccKey.BCRYPT_ECDH_PUBLIC_P256_MAGIC);
                }
                else
                {
                    numArray4 = (flag ? EccKey.BCRYPT_ECDSA_PRIVATE_P256_MAGIC : EccKey.BCRYPT_ECDH_PRIVATE_P256_MAGIC);
                }
                numArray = numArray4;
            }
            else if (length != 48)
            {
                if (length != 66)
                {
                    throw new ArgumentException("Size of X,Y or D must equal to 32, 48 or 66 bytes");
                }
                if (d == null)
                {
                    numArray2 = (flag ? EccKey.BCRYPT_ECDSA_PUBLIC_P521_MAGIC : EccKey.BCRYPT_ECDH_PUBLIC_P521_MAGIC);
                }
                else
                {
                    numArray2 = (flag ? EccKey.BCRYPT_ECDSA_PRIVATE_P521_MAGIC : EccKey.BCRYPT_ECDH_PRIVATE_P521_MAGIC);
                }
                numArray = numArray2;
            }
            else
            {
                if (d == null)
                {
                    numArray3 = (flag ? EccKey.BCRYPT_ECDSA_PUBLIC_P384_MAGIC : EccKey.BCRYPT_ECDH_PUBLIC_P384_MAGIC);
                }
                else
                {
                    numArray3 = (flag ? EccKey.BCRYPT_ECDSA_PRIVATE_P384_MAGIC : EccKey.BCRYPT_ECDH_PRIVATE_P384_MAGIC);
                }
                numArray = numArray3;
            }
            byte[] bytes = BitConverter.GetBytes(length);
            if (d != null)
            {
                numArray1 = Arrays.Concat(new byte[][] { numArray, bytes, x, y, d });
                eccPrivateBlob = CngKeyBlobFormat.EccPrivateBlob;
            }
            else
            {
                numArray1 = Arrays.Concat(new byte[][] { numArray, bytes, x, y });
                eccPrivateBlob = CngKeyBlobFormat.EccPublicBlob;
            }
            return CngKey.Import(numArray1, eccPrivateBlob);
        }
    }
}