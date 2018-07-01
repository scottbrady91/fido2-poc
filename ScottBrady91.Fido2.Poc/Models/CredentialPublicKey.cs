using Newtonsoft.Json;

namespace ScottBrady91.Fido2.Poc.Models
{
    public class CredentialPublicKey
    {
        [JsonProperty("1")]
        public string KeyType { get; set; }

        [JsonProperty("3")]
        public string Algorithm { get; set; }

        [JsonProperty("-1")]
        public string Curve { get; set; }

        [JsonProperty("-2")]
        public string X { get; set; }

        [JsonProperty("-3")]
        public string Y { get; set; }
    }
}