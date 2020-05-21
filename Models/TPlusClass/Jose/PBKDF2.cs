using System;
using System.Security.Cryptography;

namespace Jose
{
    public static class PBKDF2
    {
        public static byte[] DeriveKey(byte[] password, byte[] salt, int iterationCount, int keyBitLength, HMAC prf)
        {
            prf.Key = password;
            ulong num = unchecked((ulong)-1);
            object[] objArray = new object[] { keyBitLength };
            Ensure.MaxValue(keyBitLength, (long)num, "PBKDF2 expect derived key size to be not more that (2^32-1) bits, but was requested {0} bits.", objArray);
            int hashSize = prf.HashSize / 8;
            int num1 = keyBitLength / 8;
            int num2 = (int)Math.Ceiling((double)num1 / (double)hashSize);
            int num3 = num1 - (num2 - 1) * hashSize;
            byte[][] numArray = new byte[num2][];
            for (int i = 0; i < num2; i++)
            {
                numArray[i] = PBKDF2.F(salt, iterationCount, i + 1, prf);
            }
            numArray[num2 - 1] = Arrays.LeftmostBits(numArray[num2 - 1], num3 * 8);
            return Arrays.Concat(numArray);
        }

        private static byte[] F(byte[] salt, int iterationCount, int blockIndex, HMAC prf)
        {
            byte[] numArray = prf.ComputeHash(Arrays.Concat(new byte[][] { salt, Arrays.IntToBytes(blockIndex) }));
            byte[] numArray1 = numArray;
            for (int i = 2; i <= iterationCount; i++)
            {
                numArray = prf.ComputeHash(numArray);
                numArray1 = Arrays.Xor(numArray1, numArray);
            }
            return numArray1;
        }
    }
}