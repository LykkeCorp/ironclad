// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

using System;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Ironclad.Client;
using Ironclad.Tests.Sdk;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace Ironclad.Tests.Integration
{
    public class IdentityProviderManagement : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private const string IdentityProviderPrefix = "idprvd-test";

        public IdentityProviderManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task CanAddProviderMinimum()
        {
            // arrange
            var expectedProvider = CreateMinimumProvider();

            // act
            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(expectedProvider).ConfigureAwait(false);

            // assert
            var actualProvider = await _fixture.IdentityProvidersClient.GetIdentityProviderAsync(expectedProvider.Name).ConfigureAwait(false);
            actualProvider.Should().NotBeNull();
            actualProvider.Name.Should().Be(expectedProvider.Name);
            actualProvider.Authority.Should().Be(expectedProvider.Authority);
            actualProvider.ClientId.Should().Be(expectedProvider.ClientId);
        }

        [Fact]
        public async Task CanAddProvider()
        {
            var expectedProvider = new IdentityProvider
            {
                Name = GetProviderName(),
                DisplayName = $"{nameof(IdentityProviderManagement)}.{nameof(CanAddProvider)} (integration test)",
                Authority = "https://auth-test.lykkecloud.com",
                ClientId = "test-oidc",
                CallbackPath = "/test",
                AcrValues = { "idp:lykke", "tenant:ironclad" },
                Scopes = { "phone", "email" },
                AutoProvision = true,
            };

            // act
            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(expectedProvider).ConfigureAwait(false);

            // assert
            var actualProvider = await _fixture.IdentityProvidersClient.GetIdentityProviderAsync(expectedProvider.Name).ConfigureAwait(false);
            actualProvider.Should().NotBeNull();
            actualProvider.Should().BeEquivalentTo(expectedProvider);
        }

        [Fact]
        public async Task CanGetProviderSummaries()
        {
            // arrange
            var expectedProvider = CreateMinimumProvider();

            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(expectedProvider).ConfigureAwait(false);

            // act
            var providerSummaries = await _fixture.IdentityProvidersClient.GetIdentityProviderSummariesAsync().ConfigureAwait(false);

            // assert
            providerSummaries.Should().NotBeNull();
            providerSummaries.Should()
                .Contain(summary =>
                    summary.Name == expectedProvider.Name && summary.ClientId == expectedProvider.ClientId &&
                    summary.Authority == expectedProvider.Authority);
        }

        [Fact]
        public async Task CanGetClientSummariesWithQuery()
        {
            // arrange
            var provider1 = CreateMinimumProvider($"{IdentityProviderPrefix}_test");
            var provider2 = CreateMinimumProvider($"{IdentityProviderPrefix}_test_02");
            var provider3 = CreateMinimumProvider($"{IdentityProviderPrefix}_test_03");

            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider1).ConfigureAwait(false);
            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider2).ConfigureAwait(false);
            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider3).ConfigureAwait(false);

            // act
            var providerSummaries = await _fixture.IdentityProvidersClient.GetIdentityProviderSummariesAsync($"{IdentityProviderPrefix}_test_").ConfigureAwait(false);

            // assert
            providerSummaries.Should().NotBeNull();
            providerSummaries.Should().HaveCount(2);
            providerSummaries.Should().Contain(summary => summary.Name == provider2.Name);
            providerSummaries.Should().Contain(summary => summary.Name == provider3.Name);
        }

        [Fact]
        public async Task CanRemoveProvider()
        {
            // arrange
            var provider = CreateMinimumProvider();

            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            // act
            await _fixture.IdentityProvidersClient.RemoveIdentityProviderAsync(provider.Name).ConfigureAwait(false);

            // assert
            var clientSummaries = await _fixture.IdentityProvidersClient.GetIdentityProviderSummariesAsync().ConfigureAwait(false);
            clientSummaries.Should().NotBeNull();
            clientSummaries.Should().NotContain(summary => summary.Name == provider.Name);
        }

        [Fact]
        public void CannotAddBlankProvider()
        {
            // arrange
            var provider = new IdentityProvider();

            // act
            Func<Task> func = async () => await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public void CannotAddProviderWithBadCallback()
        {
            // arrange
            var provider = CreateMinimumProvider();
            provider.CallbackPath = "nonsense";

            // act
            Func<Task> func = async () => await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public void CannotAddProviderWithNoAuthority()
        {
            // arrange
            var provider = CreateMinimumProvider();
            provider.Authority = null;

            // act
            Func<Task> func = async () => await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public void CannotAddProviderWithNoClientId()
        {
            // arrange
            var provider = CreateMinimumProvider();
            provider.ClientId = null;

            // act
            Func<Task> func = async () => await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CannotAddDuplicateProvider()
        {
            // arrange
            var provider = CreateMinimumProvider();

            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        [Fact]
        public async Task CanUseExternalProvider()
        {
            // arrange
            var provider = new IdentityProvider
            {
                Name = GetProviderName(),
                Authority = "https://demo.identityserver.io",
                ClientId = "implicit",
                AcrValues = { "tenant:abc", "something:amazing" },
                Scopes = { "email", "profile" },
                CallbackPath = "/signin-idsvr",
                DisplayName = "IdentityServer (Demo)"
            };

            await _fixture.IdentityProvidersClient.AddIdentityProviderAsync(provider).ConfigureAwait(false);

            var automation = new BrowserAutomation(null, null);
            var url = Authority + "/signin";

            // act
            await automation.NavigateToLoginAsync(url).ConfigureAwait(false);
            var authorizeResponse = await automation.LoginToAuthorizationServerAndCaptureRedirectAsync(provider.Name).ConfigureAwait(false);

            // assert
            authorizeResponse.IsError.Should().BeFalse();
            var queryString = new Uri(authorizeResponse.Raw).Query;
            var queryDictionary = QueryHelpers.ParseQuery(queryString);
            queryDictionary.Should().ContainKey("ReturnUrl");
            var returnUrlQueryString = queryDictionary["ReturnUrl"];
            var returnUrlQueryDictionary = QueryHelpers.ParseQuery(returnUrlQueryString);
            returnUrlQueryDictionary.Should().ContainKey("/connect/authorize/callback?client_id");
            returnUrlQueryDictionary["/connect/authorize/callback?client_id"].ToString().Should().Be(provider.ClientId);
            returnUrlQueryDictionary.Should().ContainKey("redirect_uri");
            returnUrlQueryDictionary["redirect_uri"].ToString().Should().EndWith(provider.CallbackPath);
            returnUrlQueryDictionary.Should().ContainKey("scope");
            returnUrlQueryDictionary["scope"].ToString().Split(' ').Should().Contain(provider.Scopes);
            returnUrlQueryDictionary.Should().ContainKey("acr_values");
            returnUrlQueryDictionary["acr_values"].ToString().Split(' ').Should().Contain(provider.AcrValues);
        }

        private static IdentityProvider CreateMinimumProvider(string name = null)
        {
            // Would much rather use something like Autofixture and not worry about this, but for now...
            return new IdentityProvider
            {
                Name = name ?? GetProviderName(),
                Authority = "https://auth-test.lykkecloud.com",
                ClientId = "test-oidc"
            };
        }

        public void Dispose()
        {
            var providers = _fixture.IdentityProvidersClient.GetIdentityProviderSummariesAsync(IdentityProviderPrefix)
                .GetAwaiter().GetResult();

            foreach (var provider in providers)
            {
                _fixture.IdentityProvidersClient.RemoveIdentityProviderAsync(provider.Name).GetAwaiter().GetResult();
            }
        }

        private static string GetProviderName() => $"{IdentityProviderPrefix}-{Guid.NewGuid():N}";
    }
}
