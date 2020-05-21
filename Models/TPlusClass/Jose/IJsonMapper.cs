using System;

namespace Jose
{
	public interface IJsonMapper
	{
		T Parse<T>(string json);

		string Serialize(object obj);
	}
}