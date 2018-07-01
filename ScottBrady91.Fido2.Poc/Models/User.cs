namespace ScottBrady91.Fido2.Poc.Models
{
    public class User
    {
        public string Username { get; set; }
        public string CredentialId { get; set; }
        public CredentialPublicKey PublicKey { get; set; }
        public int Counter { get; set; }
    }
}