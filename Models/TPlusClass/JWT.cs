using Jose;
using Jose.jwe;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Middleware.Target.TPlus_V12_3.Models.TPlusClass
{
    public static class JWT

    {
        private static Dictionary<JwsAlgorithm, IJwsAlgorithm> HashAlgorithms;

        private static Dictionary<JweEncryption, IJweAlgorithm> EncAlgorithms;

        private static Dictionary<JweAlgorithm, IKeyManagement> KeyAlgorithms;

        private static Dictionary<JweCompression, ICompression> CompressionAlgorithms;

        private static Dictionary<JweAlgorithm, string> JweAlgorithms;

        private static Dictionary<JweEncryption, string> JweEncryptionMethods;

        private static Dictionary<JweCompression, string> JweCompressionMethods;

        private static Dictionary<JwsAlgorithm, string> JwsAlgorithms;

        private static Dictionary<string, JweEncryption> JweEncryptionMethodAliases;

        private static IJsonMapper jsMapper;

        public static IJsonMapper JsonMapper
        {
            set
            {
                JWT.jsMapper = value;
            }
        }

        static JWT()
        {
            JWT.JweAlgorithms = new Dictionary<JweAlgorithm, string>();
            JWT.JweEncryptionMethods = new Dictionary<JweEncryption, string>();
            JWT.JweCompressionMethods = new Dictionary<JweCompression, string>();
            JWT.JwsAlgorithms = new Dictionary<JwsAlgorithm, string>();
            JWT.JweEncryptionMethodAliases = new Dictionary<string, JweEncryption>();
            JWT.JsonMapper = new JSSerializerMapper();
            JWT.HashAlgorithms = new Dictionary<JwsAlgorithm, IJwsAlgorithm>()
            {
                { JwsAlgorithm.none, new Plaintext() },
                { JwsAlgorithm.HS256, new HmacUsingSha("SHA256") },
                { JwsAlgorithm.HS384, new HmacUsingSha("SHA384") },
                { JwsAlgorithm.HS512, new HmacUsingSha("SHA512") },
                { JwsAlgorithm.RS256, new RsaUsingSha("SHA256") },
                { JwsAlgorithm.RS384, new RsaUsingSha("SHA384") },
                { JwsAlgorithm.RS512, new RsaUsingSha("SHA512") },
                { JwsAlgorithm.ES256, new EcdsaUsingSha(256) },
                { JwsAlgorithm.ES384, new EcdsaUsingSha(384) },
                { JwsAlgorithm.ES512, new EcdsaUsingSha(521) }
            };
            JWT.JwsAlgorithms[JwsAlgorithm.none] = "none";
            JWT.JwsAlgorithms[JwsAlgorithm.HS256] = "HS256";
            JWT.JwsAlgorithms[JwsAlgorithm.HS384] = "HS384";
            JWT.JwsAlgorithms[JwsAlgorithm.HS512] = "HS512";
            JWT.JwsAlgorithms[JwsAlgorithm.RS256] = "RS256";
            JWT.JwsAlgorithms[JwsAlgorithm.RS384] = "RS384";
            JWT.JwsAlgorithms[JwsAlgorithm.RS512] = "RS512";
            JWT.JwsAlgorithms[JwsAlgorithm.ES256] = "ES256";
            JWT.JwsAlgorithms[JwsAlgorithm.ES384] = "ES384";
            JWT.JwsAlgorithms[JwsAlgorithm.ES512] = "ES512";
            JWT.HashAlgorithms[JwsAlgorithm.PS256] = new RsaPssUsingSha(32);
            JWT.HashAlgorithms[JwsAlgorithm.PS384] = new RsaPssUsingSha(48);
            JWT.HashAlgorithms[JwsAlgorithm.PS512] = new RsaPssUsingSha(64);
            JWT.JwsAlgorithms[JwsAlgorithm.PS256] = "PS256";
            JWT.JwsAlgorithms[JwsAlgorithm.PS384] = "PS384";
            JWT.JwsAlgorithms[JwsAlgorithm.PS512] = "PS512";
            JWT.EncAlgorithms = new Dictionary<JweEncryption, IJweAlgorithm>()
            {
                { JweEncryption.A128CBC_HS256, new AesCbcHmacEncryption(JWT.HashAlgorithms[JwsAlgorithm.HS256], 256) },
                { JweEncryption.A192CBC_HS384, new AesCbcHmacEncryption(JWT.HashAlgorithms[JwsAlgorithm.HS384], 384) },
                { JweEncryption.A256CBC_HS512, new AesCbcHmacEncryption(JWT.HashAlgorithms[JwsAlgorithm.HS512], 512) }
            };
            JWT.JweEncryptionMethods[JweEncryption.A128CBC_HS256] = "A128CBC-HS256";
            JWT.JweEncryptionMethods[JweEncryption.A192CBC_HS384] = "A192CBC-HS384";
            JWT.JweEncryptionMethods[JweEncryption.A256CBC_HS512] = "A256CBC-HS512";
            JWT.JweEncryptionMethodAliases["A128CBC+HS256"] = JweEncryption.A128CBC_HS256;
            JWT.JweEncryptionMethodAliases["A192CBC+HS384"] = JweEncryption.A192CBC_HS384;
            JWT.JweEncryptionMethodAliases["A256CBC+HS512"] = JweEncryption.A256CBC_HS512;
            JWT.EncAlgorithms[JweEncryption.A128GCM] = new AesGcmEncryption(128);
            JWT.EncAlgorithms[JweEncryption.A192GCM] = new AesGcmEncryption(192);
            JWT.EncAlgorithms[JweEncryption.A256GCM] = new AesGcmEncryption(256);
            JWT.JweEncryptionMethods[JweEncryption.A128GCM] = "A128GCM";
            JWT.JweEncryptionMethods[JweEncryption.A192GCM] = "A192GCM";
            JWT.JweEncryptionMethods[JweEncryption.A256GCM] = "A256GCM";
            JWT.KeyAlgorithms = new Dictionary<JweAlgorithm, IKeyManagement>()
            {
                { JweAlgorithm.RSA_OAEP, new RsaKeyManagement(true, false) },
                { JweAlgorithm.RSA_OAEP_256, new RsaKeyManagement(true, true) },
                { JweAlgorithm.RSA1_5, new RsaKeyManagement(false, false) },
                { JweAlgorithm.DIR, new DirectKeyManagement() },
                { JweAlgorithm.A128KW, new AesKeyWrapManagement(128) },
                { JweAlgorithm.A192KW, new AesKeyWrapManagement(192) },
                { JweAlgorithm.A256KW, new AesKeyWrapManagement(256) },
                { JweAlgorithm.ECDH_ES, new EcdhKeyManagement(true) },
                { JweAlgorithm.ECDH_ES_A128KW, new EcdhKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128)) },
                { JweAlgorithm.ECDH_ES_A192KW, new EcdhKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192)) },
                { JweAlgorithm.ECDH_ES_A256KW, new EcdhKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256)) },
                { JweAlgorithm.PBES2_HS256_A128KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(128, new AesKeyWrapManagement(128)) },
                { JweAlgorithm.PBES2_HS384_A192KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(192, new AesKeyWrapManagement(192)) },
                { JweAlgorithm.PBES2_HS512_A256KW, new Pbse2HmacShaKeyManagementWithAesKeyWrap(256, new AesKeyWrapManagement(256)) },
                { JweAlgorithm.A128GCMKW, new AesGcmKeyWrapManagement(128) },
                { JweAlgorithm.A192GCMKW, new AesGcmKeyWrapManagement(192) },
                { JweAlgorithm.A256GCMKW, new AesGcmKeyWrapManagement(256) }
            };
            JWT.JweAlgorithms[JweAlgorithm.RSA1_5] = "RSA1_5";
            JWT.JweAlgorithms[JweAlgorithm.RSA_OAEP] = "RSA-OAEP";
            JWT.JweAlgorithms[JweAlgorithm.RSA_OAEP_256] = "RSA-OAEP-256";
            JWT.JweAlgorithms[JweAlgorithm.DIR] = "dir";
            JWT.JweAlgorithms[JweAlgorithm.A128KW] = "A128KW";
            JWT.JweAlgorithms[JweAlgorithm.A192KW] = "A192KW";
            JWT.JweAlgorithms[JweAlgorithm.A256KW] = "A256KW";
            JWT.JweAlgorithms[JweAlgorithm.ECDH_ES] = "ECDH-ES";
            JWT.JweAlgorithms[JweAlgorithm.ECDH_ES_A128KW] = "ECDH-ES+A128KW";
            JWT.JweAlgorithms[JweAlgorithm.ECDH_ES_A192KW] = "ECDH-ES+A192KW";
            JWT.JweAlgorithms[JweAlgorithm.ECDH_ES_A256KW] = "ECDH-ES+A256KW";
            JWT.JweAlgorithms[JweAlgorithm.PBES2_HS256_A128KW] = "PBES2-HS256+A128KW";
            JWT.JweAlgorithms[JweAlgorithm.PBES2_HS384_A192KW] = "PBES2-HS384+A192KW";
            JWT.JweAlgorithms[JweAlgorithm.PBES2_HS512_A256KW] = "PBES2-HS512+A256KW";
            JWT.JweAlgorithms[JweAlgorithm.A128GCMKW] = "A128GCMKW";
            JWT.JweAlgorithms[JweAlgorithm.A192GCMKW] = "A192GCMKW";
            JWT.JweAlgorithms[JweAlgorithm.A256GCMKW] = "A256GCMKW";
            JWT.CompressionAlgorithms = new Dictionary<JweCompression, ICompression>()
            {
                { JweCompression.DEF, new DeflateCompression() }
            };
            JWT.JweCompressionMethods[JweCompression.DEF] = "DEF";
        }

        public static string Decode(string token, object key, JweAlgorithm alg, JweEncryption enc)
        {
            JwsAlgorithm? nullable = null;
            return JWT.Decode(token, key, nullable, new JweAlgorithm?(alg), new JweEncryption?(enc));
        }

        public static string Decode(string token, object key, JwsAlgorithm alg)
        {
            JweAlgorithm? nullable = null;
            JweEncryption? nullable1 = null;
            return JWT.Decode(token, key, new JwsAlgorithm?(alg), nullable, nullable1);
        }

        public static string Decode(string token, object key = null)
        {
            return JWT.Decode(token, key, null, null, null);
        }

        public static T Decode<T>(string token, object key, JweAlgorithm alg, JweEncryption enc)
        {
            return JWT.jsMapper.Parse<T>(JWT.Decode(token, key, alg, enc));
        }

        public static T Decode<T>(string token, object key, JwsAlgorithm alg)
        {
            return JWT.jsMapper.Parse<T>(JWT.Decode(token, key, alg));
        }

        public static T Decode<T>(string token, object key = null)
        {
            return JWT.jsMapper.Parse<T>(JWT.Decode(token, key));
        }

        private static string Decode(string token, object key = null, JwsAlgorithm? jwsAlg = null, JweAlgorithm? jweAlg = null, JweEncryption? jweEnc = null)
        {
            byte[] numArray = JWT.DecodeBytes(token, key, jwsAlg, jweAlg, jweEnc);
            return Encoding.UTF8.GetString(numArray);
        }

        public static byte[] DecodeBytes(string token, object key, JweAlgorithm alg, JweEncryption enc)
        {
            JwsAlgorithm? nullable = null;
            return JWT.DecodeBytes(token, key, nullable, new JweAlgorithm?(alg), new JweEncryption?(enc));
        }

        public static byte[] DecodeBytes(string token, object key, JwsAlgorithm alg)
        {
            JweAlgorithm? nullable = null;
            JweEncryption? nullable1 = null;
            return JWT.DecodeBytes(token, key, new JwsAlgorithm?(alg), nullable, nullable1);
        }

        public static byte[] DecodeBytes(string token, object key = null)
        {
            return JWT.DecodeBytes(token, key, null, null, null);
        }

        private static byte[] DecodeBytes(string token, object key = null, JwsAlgorithm? jwsAlg = null, JweAlgorithm? jweAlg = null, JweEncryption? jweEnc = null)
        {
            Ensure.IsNotEmpty(token, "Incoming token expected to be in compact serialization form, not empty, whitespace or null.", new object[0]);
            byte[][] numArray = Compact.Parse(token);
            if ((int)numArray.Length == 5)
            {
                return JWT.DecryptBytes(numArray, key, jweAlg, jweEnc);
            }
            byte[] numArray1 = numArray[0];
            byte[] numArray2 = numArray[1];
            byte[] numArray3 = numArray[2];
            byte[] bytes = Encoding.UTF8.GetBytes(Compact.Serialize(new byte[][] { numArray1, numArray2 }));
            string item = (string)JWT.jsMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(numArray1))["alg"];
            if (jwsAlg.HasValue && jwsAlg.Value != JWT.GetHashAlgorithm(item))
            {
                throw new InvalidAlgorithmException("The algorithm type passed to the Decode method did not match the algorithm type in the header.");
            }
            if (!JWT.HashAlgorithms[JWT.GetHashAlgorithm(item)].Verify(numArray3, bytes, key))
            {
                throw new IntegrityException("Invalid signature.");
            }
            return numArray2;
        }

        private static string Decrypt(byte[][] parts, object key, JweAlgorithm? jweAlg, JweEncryption? jweEnc)
        {
            byte[] numArray = JWT.DecryptBytes(parts, key, jweAlg, jweEnc);
            return Encoding.UTF8.GetString(numArray);
        }

        private static byte[] DecryptBytes(byte[][] parts, object key, JweAlgorithm? jweAlg, JweEncryption? jweEnc)
        {
            byte[] numArray = parts[0];
            byte[] numArray1 = parts[1];
            byte[] numArray2 = parts[2];
            byte[] numArray3 = parts[3];
            byte[] numArray4 = parts[4];
            IDictionary<string, object> strs = JWT.jsMapper.Parse<Dictionary<string, object>>(Encoding.UTF8.GetString(numArray));
            IKeyManagement item = JWT.KeyAlgorithms[JWT.GetJweAlgorithm((string)strs["alg"])];
            IJweAlgorithm jweAlgorithm = JWT.EncAlgorithms[JWT.GetJweEncryption((string)strs["enc"])];
            if (jweAlg.HasValue && jweAlg.Value != JWT.GetJweAlgorithm((string)strs["alg"]))
            {
                throw new InvalidAlgorithmException("The algorithm type passed to the Decrypt method did not match the algorithm type in the header.");
            }
            if (jweEnc.HasValue && jweEnc.Value != JWT.GetJweEncryption((string)strs["enc"]))
            {
                throw new InvalidAlgorithmException("The encryption type passed to the Decrypt method did not match the encryption type in the header.");
            }
            byte[] numArray5 = item.Unwrap(numArray1, key, jweAlgorithm.KeySize, strs);
            byte[] bytes = Encoding.UTF8.GetBytes(Compact.Serialize(new byte[][] { numArray }));
            byte[] numArray6 = jweAlgorithm.Decrypt(bytes, numArray5, numArray2, numArray3, numArray4);
            if (strs.ContainsKey("zip"))
            {
                numArray6 = JWT.CompressionAlgorithms[JWT.GetJweCompression((string)strs["zip"])].Decompress(numArray6);
            }
            return numArray6;
        }

        public static string Encode(object payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null)
        {
            return JWT.Encode(JsonConvert.SerializeObject(payload), key, alg, enc, compression, extraHeaders);
        }

        public static string Encode(string payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null)
        {
            Ensure.IsNotEmpty(payload, "Payload expected to be not empty, whitespace or null.", new object[0]);
            return JWT.EncodeBytes(Encoding.UTF8.GetBytes(payload), key, alg, enc, compression, extraHeaders);
        }

        public static string Encode(object payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null)
        {
            return JWT.Encode(JsonConvert.SerializeObject(payload), key, algorithm, extraHeaders);
        }

        public static string Encode(string payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null)
        {
            Ensure.IsNotEmpty(payload, "Payload expected to be not empty, whitespace or null.", new object[0]);
            return JWT.EncodeBytes(Encoding.UTF8.GetBytes(payload), key, algorithm, extraHeaders);
        }

        public static string EncodeBytes(byte[] payload, object key, JweAlgorithm alg, JweEncryption enc, JweCompression? compression = null, IDictionary<string, object> extraHeaders = null)
        {
            if (payload == null)
            {
                throw new ArgumentNullException("payload");
            }
            IKeyManagement item = JWT.KeyAlgorithms[alg];
            IJweAlgorithm jweAlgorithm = JWT.EncAlgorithms[enc];
            IDictionary<string, object> strs = new Dictionary<string, object>()
            {
                { "alg", JWT.JweAlgorithms[alg] },
                { "enc", JWT.JweEncryptionMethods[enc] }
            };
            Dictionaries.Append<string, object>(strs, extraHeaders);
            byte[][] numArray = item.WrapNewKey(jweAlgorithm.KeySize, key, strs);
            byte[] numArray1 = numArray[0];
            byte[] numArray2 = numArray[1];
            if (compression.HasValue)
            {
                strs["zip"] = JWT.JweCompressionMethods[compression.Value];
                payload = JWT.CompressionAlgorithms[compression.Value].Compress(payload);
            }
            byte[] bytes = Encoding.UTF8.GetBytes(JWT.jsMapper.Serialize(strs));
            byte[] bytes1 = Encoding.UTF8.GetBytes(Compact.Serialize(new byte[][] { bytes }));
            byte[][] numArray3 = jweAlgorithm.Encrypt(bytes1, payload, numArray1);
            return Compact.Serialize(new byte[][] { bytes, numArray2, numArray3[0], numArray3[1], numArray3[2] });
        }

        public static string EncodeBytes(byte[] payload, object key, JwsAlgorithm algorithm, IDictionary<string, object> extraHeaders = null)
        {
            if (payload == null)
            {
                throw new ArgumentNullException("payload");
            }
            if (extraHeaders == null)
            {
                extraHeaders = new Dictionary<string, object>()
                {
                    { "typ", "JWT" }
                };
            }
            Dictionary<string, object> strs = new Dictionary<string, object>()
            {
                { "alg", JWT.JwsAlgorithms[algorithm] }
            };
            Dictionaries.Append<string, object>(strs, extraHeaders);
            byte[] bytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(strs));
            byte[] numArray = Encoding.UTF8.GetBytes(Compact.Serialize(new byte[][] { bytes, payload }));
            //byte[] numArray1 = JWT.HashAlgorithms[algorithm].Sign(numArray, key);
            SHA512 sha1 = SHA512.Create();
            byte[] numArray1 = sha1.ComputeHash(numArray);
            //System.Security.Cryptography.SHA512Cng  --
            return Compact.Serialize(new byte[][] { bytes, payload, numArray1 });
        }


        private static JwsAlgorithm GetHashAlgorithm(string algorithm)
        {
            JwsAlgorithm key;
            Dictionary<JwsAlgorithm, string>.Enumerator enumerator = JWT.JwsAlgorithms.GetEnumerator();
            try
            {
                while (enumerator.MoveNext())
                {
                    KeyValuePair<JwsAlgorithm, string> current = enumerator.Current;
                    if (!current.Value.Equals(algorithm))
                    {
                        continue;
                    }
                    key = current.Key;
                    return key;
                }
                throw new InvalidAlgorithmException(string.Format("Signing algorithm is not supported: {0}", algorithm));
            }
            finally
            {
                ((IDisposable)enumerator).Dispose();
            }
            return key;
        }

        private static JweAlgorithm GetJweAlgorithm(string algorithm)
        {
            JweAlgorithm key;
            Dictionary<JweAlgorithm, string>.Enumerator enumerator = JWT.JweAlgorithms.GetEnumerator();
            try
            {
                while (enumerator.MoveNext())
                {
                    KeyValuePair<JweAlgorithm, string> current = enumerator.Current;
                    if (!current.Value.Equals(algorithm))
                    {
                        continue;
                    }
                    key = current.Key;
                    return key;
                }
                throw new InvalidAlgorithmException(string.Format("Algorithm is not supported: {0}.", algorithm));
            }
            finally
            {
                ((IDisposable)enumerator).Dispose();
            }
            return key;
        }

        private static JweCompression GetJweCompression(string algorithm)
        {
            JweCompression key;
            Dictionary<JweCompression, string>.Enumerator enumerator = JWT.JweCompressionMethods.GetEnumerator();
            try
            {
                while (enumerator.MoveNext())
                {
                    KeyValuePair<JweCompression, string> current = enumerator.Current;
                    if (!current.Value.Equals(algorithm))
                    {
                        continue;
                    }
                    key = current.Key;
                    return key;
                }
                throw new InvalidAlgorithmException(string.Format("Compression algorithm is not supported: {0}.", algorithm));
            }
            finally
            {
                ((IDisposable)enumerator).Dispose();
            }
            return key;
        }

        private static JweEncryption GetJweEncryption(string algorithm)
        {
            JweEncryption jweEncryption;
            JweEncryption key;
            Dictionary<JweEncryption, string>.Enumerator enumerator = JWT.JweEncryptionMethods.GetEnumerator();
            try
            {
                while (enumerator.MoveNext())
                {
                    KeyValuePair<JweEncryption, string> current = enumerator.Current;
                    if (!current.Value.Equals(algorithm))
                    {
                        continue;
                    }
                    key = current.Key;
                    return key;
                }
                if (!JWT.JweEncryptionMethodAliases.TryGetValue(algorithm, out jweEncryption))
                {
                    throw new InvalidAlgorithmException(string.Format("Encryption algorithm is not supported: {0}.", algorithm));
                }
                return jweEncryption;
            }
            finally
            {
                ((IDisposable)enumerator).Dispose();
            }
            return key;
        }

        public static IDictionary<string, object> Headers(string token)
        {
            return JWT.Headers<IDictionary<string, object>>(token);
        }

        public static T Headers<T>(string token)
        {
            byte[][] numArray = Compact.Parse(token);
            return JWT.jsMapper.Parse<T>(Encoding.UTF8.GetString(numArray[0]));
        }

        public static string Payload(string token)
        {
            byte[][] numArray = Compact.Parse(token);
            if ((int)numArray.Length > 3)
            {
                throw new JoseException("Getting payload for encrypted tokens is not supported. Please use Jose.JWT.Decode() method instead.");
            }
            return Encoding.UTF8.GetString(numArray[1]);
        }

        public static T Payload<T>(string token)
        {
            return JWT.jsMapper.Parse<T>(JWT.Payload(token));
        }

        public static byte[] PayloadBytes(string token)
        {
            byte[][] numArray = Compact.Parse(token);
            if ((int)numArray.Length > 3)
            {
                throw new JoseException("Getting payload for encrypted tokens is not supported. Please use Jose.JWT.Decode() method instead.");
            }
            return numArray[1];
        }
    }
}
