using System;

namespace Jose
{
	public class InvalidAlgorithmException : JoseException
	{
		public InvalidAlgorithmException(string message) : base(message)
		{
		}

		public InvalidAlgorithmException(string message, Exception innerException) : base(message, innerException)
		{
		}
	}
}