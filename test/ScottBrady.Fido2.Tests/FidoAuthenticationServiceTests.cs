using Microsoft.Extensions.Options;
using Moq;
using ScottBrady.Fido2.Cryptography;
using ScottBrady.Fido2.Parsers;
using ScottBrady.Fido2.Stores;
using Xunit;

namespace ScottBrady.Fido2.Tests;

public class FidoAuthenticationServiceTests
{
    private readonly Mock<IClientDataParser> mockClientDataParser = new Mock<IClientDataParser>();
    private readonly Mock<IAuthenticatorDataParser> mockAuthenticatorDataParser = new Mock<IAuthenticatorDataParser>();
    private readonly Mock<IFidoSignatureValidator> mockSignatureValidator = new Mock<IFidoSignatureValidator>();
    private readonly Mock<IFidoOptionsStore> mockOptionsStore = new Mock<IFidoOptionsStore>();
    private readonly Mock<IFidoKeyStore> mockKeyStore = new Mock<IFidoKeyStore>();
    private readonly FidoOptions configurationOptions = new FidoOptions();
    
    private readonly FidoAuthenticationService sut;

    public FidoAuthenticationServiceTests()
    {
        sut = new FidoAuthenticationService(
            mockClientDataParser.Object,
            mockAuthenticatorDataParser.Object,
            mockSignatureValidator.Object,
            mockOptionsStore.Object,
            mockKeyStore.Object,
            new OptionsWrapper<FidoOptions>(configurationOptions));
    }   
    
}