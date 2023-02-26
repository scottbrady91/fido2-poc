using System.Security.Cryptography;
using FluentAssertions;
using ScottBrady.Fido2.Models;
using ScottBrady.Fido2.Stores;
using Xunit;

namespace ScottBrady.Fido2.Tests.Stores;

public class InMemoryFidoOptionsStoreTests
{
    private InMemoryFidoOptionsStore sut = new InMemoryFidoOptionsStore();

    [Fact]
    public async Task Store_RegistrationOptions_WhenOptionsDoNotExist_ExpectOptionsStored()
    {
        var options = new FidoRegistrationOptions { Challenge = RandomNumberGenerator.GetBytes(16) };

        await sut.Store(options);

        InMemoryFidoOptionsStore.RegistrationOptions[InMemoryFidoOptionsStore.CreateKey(options.Challenge)].Should().Be(options);
    }
    
    [Fact]
    public async Task Store_RegistrationOptions_WhenOptionsExist_ExpectOptionsOverwritten()
    {
        var challenge = RandomNumberGenerator.GetBytes(16);
        
        var oldOptions = new FidoRegistrationOptions { Challenge = challenge, User = new User {Id = RandomNumberGenerator.GetBytes(32)}};
        InMemoryFidoOptionsStore.RegistrationOptions[InMemoryFidoOptionsStore.CreateKey(challenge)] = oldOptions;
        
        var newOptions = new FidoRegistrationOptions { Challenge = challenge, User = new User {Id = RandomNumberGenerator.GetBytes(32)}};
        await sut.Store(newOptions);

        InMemoryFidoOptionsStore.RegistrationOptions[InMemoryFidoOptionsStore.CreateKey(challenge)].Should().Be(newOptions);
    }

    [Fact]
    public async Task TakeRegistrationOptions_WhenOptionsExist_ExpectCorrectOptions()
    {
        var challenge = RandomNumberGenerator.GetBytes(16);
        var expectedOptions = new FidoRegistrationOptions { Challenge = challenge, User = new User {Id = RandomNumberGenerator.GetBytes(32)}};
        InMemoryFidoOptionsStore.RegistrationOptions[InMemoryFidoOptionsStore.CreateKey(challenge)] = expectedOptions;

        var options = await sut.TakeRegistrationOptions(challenge);

        options.Should().Be(expectedOptions);
        InMemoryFidoOptionsStore.RegistrationOptions.ContainsKey(InMemoryFidoOptionsStore.CreateKey(challenge)).Should().BeFalse();
    }

    [Fact]
    public async Task TakeRegistrationOptions_WhenOptionsDoNotExist_ExpectNull()
    {
        var options = await sut.TakeRegistrationOptions(RandomNumberGenerator.GetBytes(16));

        options.Should().BeNull();
    }
    
    [Fact]
    public async Task Store_AuthenticationOptions_WhenOptionsDoNotExist_ExpectOptionsStored()
    {
        var options = new FidoAuthenticationOptions { Challenge = RandomNumberGenerator.GetBytes(16) };

        await sut.Store(options);

        InMemoryFidoOptionsStore.AuthenticationOptions[InMemoryFidoOptionsStore.CreateKey(options.Challenge)].Should().Be(options);
    }
    
    [Fact]
    public async Task Store_AuthenticationOptions_WhenOptionsExist_ExpectOptionsOverwritten()
    {
        var challenge = RandomNumberGenerator.GetBytes(16);
        
        var oldOptions = new FidoAuthenticationOptions { Challenge = challenge, Test = "TODO1"};
        InMemoryFidoOptionsStore.AuthenticationOptions[InMemoryFidoOptionsStore.CreateKey(challenge)] = oldOptions;
        
        var newOptions = new FidoAuthenticationOptions { Challenge = challenge, Test = "TODO2"};
        await sut.Store(newOptions);

        InMemoryFidoOptionsStore.AuthenticationOptions[InMemoryFidoOptionsStore.CreateKey(challenge)].Should().Be(newOptions);
    }

    [Fact]
    public async Task TakeAuthenticationOptions_WhenOptionsExist_ExpectCorrectOptions()
    {
        var challenge = RandomNumberGenerator.GetBytes(16);
        var expectedOptions = new FidoAuthenticationOptions { Challenge = challenge, Test = "TODO"};
        InMemoryFidoOptionsStore.AuthenticationOptions[InMemoryFidoOptionsStore.CreateKey(challenge)] = expectedOptions;

        var options = await sut.TakeAuthenticationOptions(challenge);

        options.Should().Be(expectedOptions);
        InMemoryFidoOptionsStore.AuthenticationOptions.ContainsKey(InMemoryFidoOptionsStore.CreateKey(challenge)).Should().BeFalse();
    }

    [Fact]
    public async Task TakeAuthenticationOptions_WhenOptionsDoNotExist_ExpectNull()
    {
        var options = await sut.TakeAuthenticationOptions(RandomNumberGenerator.GetBytes(16));

        options.Should().BeNull();
    }
}