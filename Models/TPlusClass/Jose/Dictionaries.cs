using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Jose
{
	public class Dictionaries
	{
		public Dictionaries()
		{
		}

		public static void Append<K, V>(IDictionary<K, V> src, IDictionary<K, V> other)
		{
			Func<KeyValuePair<K, V>, bool> func = null;
			if (src != null && other != null)
			{
				IDictionary<K, V> ks = other;
				Func<KeyValuePair<K, V>, bool> func1 = func;
				if (func1 == null)
				{
					Func<KeyValuePair<K, V>, bool> func2 = (KeyValuePair<K, V> pair) => !src.ContainsKey(pair.Key);
					Func<KeyValuePair<K, V>, bool> func3 = func2;
					func = func2;
					func1 = func3;
				}
				foreach (KeyValuePair<K, V> keyValuePair in ks.Where<KeyValuePair<K, V>>(func1))
				{
					src.Add(keyValuePair);
				}
			}
		}
	}
}