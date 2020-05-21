using System;

namespace Jose
{
	public class EncryptionException : JoseException
	{
		public EncryptionException(string message) : base(message)
		{
		}

		public EncryptionException(string message, Exception innerException) : base(message, innerException)
		{
		}
	}
}