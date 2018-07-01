namespace ScottBrady91.Fido2.Poc.Models
{
    public class FidoResponse
    {
        public string AttestationObject { get; set; }
        public string ClientDataJson { get; set; }
        public string AuthenticatorData { get; set; }
        public string Signature { get; set; }
        public string UserHandle { get; set; }
    }
}