using System;
using System.IO;
using System.Security.Cryptography;

namespace Jose
{
    public static class AesKeyWrap
    {
        private readonly static byte[] DefaultIV;

        static AesKeyWrap()
        {
            AesKeyWrap.DefaultIV = new byte[] { 166, 166, 166, 166, 166, 166, 166, 166 };
        }

        private static byte[] AesDec(byte[] sharedKey, byte[] cipherText)
        {
            byte[] array;
            using (Aes aesManaged = new AesManaged())
            {
                aesManaged.Key = sharedKey;
                aesManaged.Mode = CipherMode.ECB;
                aesManaged.Padding = PaddingMode.None;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (ICryptoTransform cryptoTransform = aesManaged.CreateDecryptor(aesManaged.Key, aesManaged.IV))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(cipherText, 0, (int)cipherText.Length);
                            cryptoStream.FlushFinalBlock();
                            array = memoryStream.ToArray();
                        }
                    }
                }
            }
            return array;
        }

        private static byte[] AesEnc(byte[] sharedKey, byte[] plainText)
        {
            byte[] array;
            using (Aes aesManaged = new AesManaged())
            {
                aesManaged.Key = sharedKey;
                aesManaged.Mode = CipherMode.ECB;
                aesManaged.Padding = PaddingMode.None;
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (ICryptoTransform cryptoTransform = aesManaged.CreateEncryptor(aesManaged.Key, aesManaged.IV))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(plainText, 0, (int)plainText.Length);
                            cryptoStream.FlushFinalBlock();
                            array = memoryStream.ToArray();
                        }
                    }
                }
            }
            return array;
        }

        public static byte[] Unwrap(byte[] encryptedCek, byte[] kek)
        {
            Ensure.MinBitSize(encryptedCek, 128, "AesKeyWrap.Unwrap() expects content length not less than 128 bits, but was {0}", new object[] { (int)encryptedCek.Length * 8 });
            Ensure.Divisible((int)encryptedCek.Length, 8, "AesKeyWrap.Unwrap() expects content length to be divisable by 8, but was given a content of {0} bit size.", new object[] { (int)encryptedCek.Length * 8 });
            byte[][] numArray = Arrays.Slice(encryptedCek, 8);
            byte[] numArray1 = numArray[0];
            byte[][] numArray2 = new byte[(int)numArray.Length - 1][];
            for (int i = 1; i < (int)numArray.Length; i++)
            {
                numArray2[i - 1] = numArray[i];
            }
            long length = (long)((int)numArray2.Length);
            for (long j = (long)5; j >= (long)0; j -= (long)1)
            {
                for (long k = length - (long)1; k >= (long)0; k -= (long)1)
                {
                    long num = length * j + k + (long)1;
                    numArray1 = Arrays.Xor(numArray1, num);
                    byte[] numArray3 = AesKeyWrap.AesDec(kek, Arrays.Concat(new byte[][] { numArray1, numArray2[checked(k)] }));
                    numArray1 = Arrays.FirstHalf(numArray3);
                    numArray2[checked(k)] = Arrays.SecondHalf(numArray3);
                }
            }
            if (!Arrays.ConstantTimeEquals(AesKeyWrap.DefaultIV, numArray1))
            {
                throw new IntegrityException("AesKeyWrap integrity check failed.");
            }
            return Arrays.Concat(numArray2);
        }

        public static byte[] Wrap(byte[] cek, byte[] kek)
        {
            Ensure.MinBitSize(cek, 128, "AesKeyWrap.Wrap() expects content length not less than 128 bits, but was {0}", new object[] { (int)cek.Length * 8 });
            Ensure.Divisible((int)cek.Length, 8, "AesKeyWrap.Wrap() expects content length to be divisable by 8, but was given a content of {0} bit size.", new object[] { (int)cek.Length * 8 });
            byte[] defaultIV = AesKeyWrap.DefaultIV;
            byte[][] numArray = Arrays.Slice(cek, 8);
            long length = (long)((int)numArray.Length);
            for (long i = (long)0; i < (long)6; i += (long)1)
            {
                for (long j = (long)0; j < length; j += (long)1)
                {
                    long num = length * i + j + (long)1;
                    byte[] numArray1 = AesKeyWrap.AesEnc(kek, Arrays.Concat(new byte[][] { defaultIV, numArray[checked(j)] }));
                    defaultIV = Arrays.FirstHalf(numArray1);
                    numArray[checked(j)] = Arrays.SecondHalf(numArray1);
                    defaultIV = Arrays.Xor(defaultIV, num);
                }
            }
            byte[][] numArray2 = new byte[checked(length + 1)][];
            numArray2[0] = defaultIV;
            for (long k = (long)1; k <= length; k += (long)1)
            {
                numArray2[checked(k)] = numArray[checked(k - (long)1)];
            }
            return Arrays.Concat(numArray2);
        }
    }
}