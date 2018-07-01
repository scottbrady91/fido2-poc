namespace ScottBrady91.Fido2.Poc.Models
{
    public class FidoLoginModel
    {
        public string Challenge { get; set; }
        public string KeyId { get; set; }
        public string RelyingPartyId { get; set; }
    }
}