using Newtonsoft.Json;
using System;

namespace Jose
{
    public class JSSerializerMapper : IJsonMapper
    {
        private static JsonSerializer js;

        private JsonSerializer JS
        {
            get
            {
                JsonSerializer javaScriptSerializer = JSSerializerMapper.js;
                if (javaScriptSerializer == null)
                {
                    javaScriptSerializer = new JsonSerializer();
                    JSSerializerMapper.js = javaScriptSerializer;
                }
                return javaScriptSerializer;
            }
        }

        public JSSerializerMapper()
        {
        }

        public T Parse<T>(string json)
        {
            return JsonConvert.DeserializeObject<T>(json);
        }

        public string Serialize(object obj)
        {
            return JsonConvert.SerializeObject(obj);
        }
    }
}