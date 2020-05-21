using System;

namespace Jose
{
	public static class Base64Url
	{
		public static byte[] Decode(string input)
		{
			string str = input;
			str = str.Replace('-', '+');
			str = str.Replace('\u005F', '/');
			switch (str.Length % 4)
			{
				case 0:
				{
					return Convert.FromBase64String(str);
				}
				case 1:
				{
					throw new ArgumentOutOfRangeException("input", "Illegal base64url string!");
				}
				case 2:
				{
					str = string.Concat(str, "==");
					return Convert.FromBase64String(str);
				}
				case 3:
				{
					str = string.Concat(str, "=");
					return Convert.FromBase64String(str);
				}
				default:
				{
					throw new ArgumentOutOfRangeException("input", "Illegal base64url string!");
				}
			}
		}

		public static string Encode(byte[] input)
		{
			return Convert.ToBase64String(input).Split(new char[] { '=' })[0].Replace('+', '-').Replace('/', '\u005F');
		}
	}
}