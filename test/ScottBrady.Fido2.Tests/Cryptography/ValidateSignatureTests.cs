using FluentAssertions;
using ScottBrady.Fido2.Cryptography;
using Xunit;

namespace ScottBrady.Fido2.Tests.Cryptography;

public class ValidateSignatureTests
{
    private static readonly byte[] TestSignature = Convert.FromBase64String("MEYCIQDL8f+Vr0Z7JBo9IMZeafX9hCrOJX9fQ5pZkPGQQu+yAgIhAOuOPJjbDN+BlouGxJpPI9WpOZ0u/12E+liI8dD0PXug");

    [Fact]
    public void DeserializeSignature()
    {
        var sut = new FidoSignatureValidator();
        var signature = sut.DeserializeSignature(TestSignature);

        signature.Should().NotBeEmpty();
    }
}