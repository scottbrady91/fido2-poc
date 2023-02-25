using FluentAssertions;
using ScottBrady.Fido2.Parsers;
using Xunit;

namespace ScottBrady.Fido2.Tests;

// Basic happy path tests using data from Windows Hello
public class HappyPathTests
{
    private readonly byte[] testClientDataJson = Convert.FromBase64String("eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVjJwUlduTE94Yi03UV9WYzVCNDk1USIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9");
    private readonly byte[] testAttestationObject = Convert.FromBase64String("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAICVrJnYJupd8EWxwKQVuGJuh6RrCDEYDMvlND9ww67qRpQECAyYgASFYIID3OZq4HO2dCKLVsbYoCdwSAhgcoxnMBPV5Si0ryBaMIlggoXBwitSsaA4PKUEIfMAHcDQLFgkgqdqNZMcJ3gXKETY=");
    
    [Fact]
    public void ClientDataParser_Parse()
    {
        var sut = new ClientDataParser();
        var clientData = sut.Parse(testClientDataJson);

        clientData.Type.Should().Be("webauthn.create");
        clientData.Origin.Should().Be("https://localhost:5000");
        clientData.Challenge.Should().Be("V2pRWnLOxb-7Q_Vc5B495Q");
        clientData.CrossOrigin.Should().Be(false);
    }
    
}