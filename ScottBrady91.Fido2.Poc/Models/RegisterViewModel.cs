namespace ScottBrady91.Fido2.Poc.Models
{
    public class RegisterViewModel
    {
        public string Username { get; set; }
        public string Challenge { get; set; }
        public string RelyingPartyId { get; set; }
    }
}