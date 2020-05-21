using System;

namespace Jose
{
	public class JoseException : Exception
	{
		public JoseException(string message) : base(message)
		{
		}

		public JoseException(string message, Exception innerException) : base(message, innerException)
		{
		}
	}
}