using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Jose
{
	public class Ensure
	{
		public Ensure()
		{
		}

		public static void BitSize(byte[] array, int expectedSize, string msg, params object[] args)
		{
			if (expectedSize != (int)array.Length * 8)
			{
				throw new ArgumentException(string.Format(msg, args));
			}
		}

		public static void BitSize(int actualSize, int expectedSize, string msg)
		{
			if (expectedSize != actualSize)
			{
				throw new ArgumentException(msg);
			}
		}

		public static void Contains(IDictionary<string, object> dict, string[] keys, string msg, params object[] args)
		{
			if (keys.Any<string>((string key) => !dict.ContainsKey(key)))
			{
				throw new ArgumentException(string.Format(msg, args));
			}
		}

		public static void Divisible(int arg, int divisor, string msg, params object[] args)
		{
			if (arg % divisor != 0)
			{
				throw new ArgumentException(string.Format(msg, args));
			}
		}

		public static void IsEmpty(byte[] arr, string msg, params object[] args)
		{
			if (arr.Length != 0)
			{
				throw new ArgumentException(msg);
			}
		}

		public static void IsNotEmpty(string arg, string msg, params object[] args)
		{
			if (string.IsNullOrWhiteSpace(arg))
			{
				throw new ArgumentException(msg);
			}
		}

		public static void IsNull(object key, string msg, params object[] args)
		{
			if (key != null)
			{
				throw new ArgumentException(msg);
			}
		}

		public static void MaxValue(int arg, long max, string msg, params object[] args)
		{
			if ((long)arg > max)
			{
				throw new ArgumentException(string.Format(msg, args));
			}
		}

		public static void MinBitSize(byte[] arr, int minBitSize, string msg, params object[] args)
		{
			Ensure.MinValue((int)arr.Length * 8, minBitSize, msg, args);
		}

		public static void MinValue(int arg, int min, string msg, params object[] args)
		{
			if (arg < min)
			{
				throw new ArgumentException(string.Format(msg, args));
			}
		}

		public static void SameSize(byte[] left, byte[] right, string msg, params object[] args)
		{
			if ((int)left.Length != (int)right.Length)
			{
				throw new ArgumentException(string.Format(msg, args));
			}
		}

		public static T Type<T>(object obj, string msg, params object[] args)
		{
			if (!(obj is T))
			{
				throw new ArgumentException(msg);
			}
			return (T)obj;
		}
	}
}