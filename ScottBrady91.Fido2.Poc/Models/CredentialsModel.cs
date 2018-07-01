namespace ScottBrady91.Fido2.Poc.Models
{
    public class CredentialsModel
    {
        public string RawId { get; set; }
        public string Id { get; set; }
        public string Type { get; set; }
        public FidoResponse Response { get; set; }
        public string Username { get; set; }
    }
}