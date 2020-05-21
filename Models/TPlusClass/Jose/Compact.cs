using System;
using System.Text;

namespace Jose
{
	public class Compact
	{
		public Compact()
		{
		}

		public static byte[][] Parse(string token)
		{
			string[] strArrays = token.Split(new char[] { '.' });
			byte[][] numArray = new byte[(int)strArrays.Length][];
			for (int i = 0; i < (int)strArrays.Length; i++)
			{
				numArray[i] = Base64Url.Decode(strArrays[i]);
			}
			return numArray;
		}

		public static string Serialize(params byte[][] parts)
		{
			StringBuilder stringBuilder = new StringBuilder();
			byte[][] numArray = parts;
			for (int i = 0; i < (int)numArray.Length; i++)
			{
				byte[] numArray1 = numArray[i];
				stringBuilder.Append(Base64Url.Encode(numArray1)).Append(".");
			}
			stringBuilder.Remove(stringBuilder.Length - 1, 1);
			return stringBuilder.ToString();
		}
	}
}