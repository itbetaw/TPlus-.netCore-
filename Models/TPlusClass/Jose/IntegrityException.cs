using System;

namespace Jose
{
	public class IntegrityException : JoseException
	{
		public IntegrityException(string message) : base(message)
		{
		}

		public IntegrityException(string message, Exception innerException) : base(message, innerException)
		{
		}
	}
}