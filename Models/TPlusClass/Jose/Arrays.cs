using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Jose
{
    public class Arrays
    {
        public readonly static byte[] Empty;

        public readonly static byte[] Zero;

        private static RandomNumberGenerator rng;

        internal static RandomNumberGenerator RNG
        {
            get
            {
                RandomNumberGenerator randomNumberGenerator = Arrays.rng;
                if (randomNumberGenerator == null)
                {
                    randomNumberGenerator = RandomNumberGenerator.Create();
                    Arrays.rng = randomNumberGenerator;
                }
                return randomNumberGenerator;
            }
        }

        static Arrays()
        {
            Arrays.Empty = new byte[0];
            Arrays.Zero = new byte[1];
        }

        public Arrays()
        {
        }

        public static long BytesToLong(byte[] array)
        {
            return (BitConverter.IsLittleEndian ? (long)(array[0] << 24 | array[1] << 16 | array[2] << 8 | array[3]) << 32 : (long)(array[7] << 24 | array[6] << 16 | array[5] << 8 | array[4]) << 32) | (BitConverter.IsLittleEndian ? (long)((long)(array[4] << 24 | array[5] << 16 | array[6] << 8 | array[7]) & unchecked((long)-1)) : (long)((long)(array[3] << 24 | array[2] << 16 | array[1] << 8 | array[0]) & (long)-1));
        }

        public static byte[] Concat(params byte[][] arrays)
        {
            byte[] numArray = new byte[((IEnumerable<byte[]>)arrays).Sum<byte[]>((byte[] a) =>
            {
                if (a == null)
                {
                    return 0;
                }
                return (int)a.Length;
            })];
            int length = 0;
            byte[][] numArray1 = arrays;
            for (int i = 0; i < (int)numArray1.Length; i++)
            {
                byte[] numArray2 = numArray1[i];
                if (numArray2 != null)
                {
                    Buffer.BlockCopy(numArray2, 0, numArray, length, (int)numArray2.Length);
                    length += (int)numArray2.Length;
                }
            }
            return numArray;
        }

        public static bool ConstantTimeEquals(byte[] expected, byte[] actual)
        {
            if (expected == actual)
            {
                return true;
            }
            if (expected == null || actual == null)
            {
                return false;
            }
            if ((int)expected.Length != (int)actual.Length)
            {
                return false;
            }
            bool flag = true;
            for (int i = 0; i < (int)expected.Length; i++)
            {
                if (expected[i] != actual[i])
                {
                    flag = false;
                }
            }
            return flag;
        }

        public static string Dump(byte[] arr, string label = "")
        {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append(string.Format("{0}({1} bytes): [", string.Concat(label, " "), (int)arr.Length).Trim());
            byte[] numArray = arr;
            for (int i = 0; i < (int)numArray.Length; i++)
            {
                stringBuilder.Append(numArray[i]);
                stringBuilder.Append(",");
            }
            stringBuilder.Remove(stringBuilder.Length - 1, 1);
            stringBuilder.Append("] Hex:[").Append(BitConverter.ToString(arr).Replace("-", " "));
            stringBuilder.Append("] Base64Url:").Append(Base64Url.Encode(arr)).Append("\n");
            return stringBuilder.ToString();
        }

        public static byte[] FirstHalf(byte[] arr)
        {
            Ensure.Divisible((int)arr.Length, 2, "Arrays.FirstHalf() expects even number of element in array.", new object[0]);
            int length = (int)arr.Length / 2;
            byte[] numArray = new byte[length];
            Buffer.BlockCopy(arr, 0, numArray, 0, length);
            return numArray;
        }

        public static byte[] IntToBytes(int value)
        {
            uint num = (uint)value;
            if (!BitConverter.IsLittleEndian)
            {
                return new byte[] { (byte)(num & 255), (byte)(num >> 8 & 255), (byte)(num >> 16 & 255), (byte)(num >> 24 & 255) };
            }
            return new byte[] { (byte)(num >> 24 & 255), (byte)(num >> 16 & 255), (byte)(num >> 8 & 255), (byte)(num & 255) };
        }

        public static byte[] LeftmostBits(byte[] data, int lengthBits)
        {
            Ensure.Divisible(lengthBits, 8, "LeftmostBits() expects length in bits divisible by 8, but was given {0}", new object[] { lengthBits });
            int num = lengthBits / 8;
            byte[] numArray = new byte[num];
            Buffer.BlockCopy(data, 0, numArray, 0, num);
            return numArray;
        }

        public static byte[] LongToBytes(long value)
        {
            ulong num = (ulong)value;
            if (!BitConverter.IsLittleEndian)
            {
                return new byte[] { (byte)(num & (long)255), (byte)(num >> 8 & (long)255), (byte)(num >> 16 & (long)255), (byte)(num >> 24 & (long)255), (byte)(num >> 32 & (long)255), (byte)(num >> 40 & (long)255), (byte)(num >> 48 & (long)255), (byte)(num >> 56 & (long)255) };
            }
            return new byte[] { (byte)(num >> 56 & (long)255), (byte)(num >> 48 & (long)255), (byte)(num >> 40 & (long)255), (byte)(num >> 32 & (long)255), (byte)(num >> 24 & (long)255), (byte)(num >> 16 & (long)255), (byte)(num >> 8 & (long)255), (byte)(num & (long)255) };
        }

        public static byte[] Random(int sizeBits = 128)
        {
            byte[] numArray = new byte[sizeBits / 8];
            Arrays.RNG.GetBytes(numArray);
            return numArray;
        }

        public static byte[] RightmostBits(byte[] data, int lengthBits)
        {
            Ensure.Divisible(lengthBits, 8, "RightmostBits() expects length in bits divisible by 8, but was given {0}", new object[] { lengthBits });
            int num = lengthBits / 8;
            byte[] numArray = new byte[num];
            Buffer.BlockCopy(data, (int)data.Length - num, numArray, 0, num);
            return numArray;
        }

        public static byte[] SecondHalf(byte[] arr)
        {
            Ensure.Divisible((int)arr.Length, 2, "Arrays.SecondHalf() expects even number of element in array.", new object[0]);
            int length = (int)arr.Length / 2;
            byte[] numArray = new byte[length];
            Buffer.BlockCopy(arr, length, numArray, 0, length);
            return numArray;
        }

        public static byte[] SixtyFourBitLength(byte[] aad)
        {
            return Arrays.LongToBytes((long)((int)aad.Length * 8));
        }

        public static byte[][] Slice(byte[] array, int count)
        {
            Ensure.MinValue(count, 1, "Arrays.Slice() expects count to be above zero, but was {0}", new object[] { count });
            Ensure.Divisible((int)array.Length, count, "Arrays.Slice() expects array length to be divisible by {0}", new object[] { count });
            int length = (int)array.Length / count;
            byte[][] numArray = new byte[length][];
            for (int i = 0; i < length; i++)
            {
                byte[] numArray1 = new byte[count];
                Buffer.BlockCopy(array, i * count, numArray1, 0, count);
                numArray[i] = numArray1;
            }
            return numArray;
        }

        public static byte[] Xor(byte[] left, long right)
        {
            Ensure.BitSize(left, 64, "Arrays.Xor(byte[], long) expects array size to be 8 bytes, but was {0}", new object[] { (int)left.Length });
            return Arrays.LongToBytes(Arrays.BytesToLong(left) ^ right);
        }

        public static byte[] Xor(byte[] left, byte[] right)
        {
            Ensure.SameSize(left, right, "Arrays.Xor(byte[], byte[]) expects both arrays to be same legnth, but was given {0} and {1}", new object[] { (int)left.Length, (int)right.Length });
            byte[] numArray = new byte[(int)left.Length];
            for (int i = 0; i < (int)left.Length; i++)
            {
                numArray[i] = (byte)(left[i] ^ right[i]);
            }
            return numArray;
        }
    }
}