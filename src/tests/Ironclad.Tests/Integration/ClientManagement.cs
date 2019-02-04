// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Integration
{
    using System;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Threading.Tasks;
    using FluentAssertions;
    using IdentityModel.Client;
    using IdentityModel.OidcClient;
    using Ironclad.Client;
    using Ironclad.Tests.Sdk;
    using Xunit;

    public class ClientManagement : AuthenticationTest
    {
        public ClientManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
        }

        [Fact]
        public async Task CanAddClientMinimum()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var expectedClient = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
            };

            // act
            await httpClient.AddClientAsync(expectedClient).ConfigureAwait(false);

            // assert
            var actualClient = await httpClient.GetClientAsync(expectedClient.Id).ConfigureAwait(false);
            actualClient.Should().NotBeNull();
            actualClient.Id.Should().Be(expectedClient.Id);
        }

        [Fact]
        public async Task CanAddClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var expectedClient = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanAddClient)} (integration test)",
                Secret = "secret",
                AllowedCorsOrigins = { "http://localhost:5005" },
                RedirectUris = { "http://localhost:5005/redirect" },
                PostLogoutRedirectUris = { "http://localhost:5005/post-logout-redirect" },
                AllowedScopes = { "role", "name" },
                AccessTokenType = "Reference",
                AllowedGrantTypes = { "implicit", "custom" },
                AllowAccessTokensViaBrowser = true,
                AllowOfflineAccess = true,
                RequireClientSecret = false,
                RequirePkce = true,
                RequireConsent = false,
                Enabled = false,
                EnableLocalLogin = false,
                AbsoluteRefreshTokenLifetime = 14,
                RefreshTokenUsage = "OneTimeOnly",
                RefreshTokenExpiration = "Sliding"
            };

            // act
            await httpClient.AddClientAsync(expectedClient).ConfigureAwait(false);

            // assert
            var actualClient = await httpClient.GetClientAsync(expectedClient.Id).ConfigureAwait(false);
            actualClient.Should().NotBeNull();
            actualClient.Should().BeEquivalentTo(expectedClient, options => options.Excluding(client => client.Secret));
        }

        [Fact]
        public async Task CanGetClientSummaries()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var expectedClient = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanGetClientSummaries)} (integration test)",
            };

            await httpClient.AddClientAsync(expectedClient).ConfigureAwait(false);

            // act
            var clientSummaries = await httpClient.GetClientSummariesAsync().ConfigureAwait(false);

            // assert
            clientSummaries.Should().NotBeNull();
            clientSummaries.Should().Contain(summary => summary.Id == expectedClient.Id && summary.Name == expectedClient.Name);
        }

        [Fact]
        public async Task CanGetClientSummariesWithQuery()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client1 = new Client { Id = "query" };
            var client2 = new Client { Id = "query_test_02" };
            var client3 = new Client { Id = "query_test_03" };

            await httpClient.AddClientAsync(client1).ConfigureAwait(false);
            await httpClient.AddClientAsync(client2).ConfigureAwait(false);
            await httpClient.AddClientAsync(client3).ConfigureAwait(false);

            // act
            var clientSummaries = await httpClient.GetClientSummariesAsync("query_").ConfigureAwait(false);

            // assert
            clientSummaries.Should().NotBeNull();
            clientSummaries.Should().HaveCount(2);
            clientSummaries.Should().Contain(summary => summary.Id == client2.Id);
            clientSummaries.Should().Contain(summary => summary.Id == client3.Id);
        }

        [Fact]
        public async Task CanModifyClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var originalClient = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanModifyClient)} (integration test)",
                Secret = "secret",
                AllowedCorsOrigins = { "http://localhost:5005" },
                RedirectUris = { "http://localhost:5005/redirect" },
                PostLogoutRedirectUris = { "http://localhost:5005/post-logout-redirect" },
                AllowedScopes = { "role", "name" },
                AccessTokenType = "Reference",
                AllowedGrantTypes = { "implicit", "custom" },
                AllowAccessTokensViaBrowser = true,
                AllowOfflineAccess = true,
                RequireClientSecret = false,
                RequirePkce = true,
                RequireConsent = false,
                Enabled = false,
                EnableLocalLogin = true,
                AbsoluteRefreshTokenLifetime = 1,
                RefreshTokenUsage = "ReUse",
                RefreshTokenExpiration = "Absolute"
            };

            var expectedClient = new Client
            {
                Id = originalClient.Id,
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanModifyClient)} (integration test) #2",
                AllowedCorsOrigins = { "http://localhost:5006" },
                RedirectUris = { "http://localhost:5006/redirect" },
                PostLogoutRedirectUris = { "http://localhost:5006/post-logout-redirect" },
                AllowedScopes = { "profile" },
                AccessTokenType = "Jwt",
                AllowedGrantTypes = { "hybrid" },
                AllowAccessTokensViaBrowser = false,
                AllowOfflineAccess = false,
                RequireClientSecret = true,
                RequirePkce = false,
                RequireConsent = true,
                Enabled = true,
                EnableLocalLogin = false,
                AbsoluteRefreshTokenLifetime = 14,
                RefreshTokenUsage = "OneTimeOnly",
                RefreshTokenExpiration = "Sliding"
            };

            await httpClient.AddClientAsync(originalClient).ConfigureAwait(false);

            // act
            await httpClient.ModifyClientAsync(expectedClient).ConfigureAwait(false);

            // assert
            var actualClient = await httpClient.GetClientAsync(expectedClient.Id).ConfigureAwait(false);
            actualClient.Should().NotBeNull();
            actualClient.Should().BeEquivalentTo(expectedClient, options => options.Excluding(client => client.Secret));
        }

        [Fact]
        public async Task CanRemoveClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanRemoveClient)} (integration test)",
            };

            await httpClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            await httpClient.RemoveClientAsync(client.Id).ConfigureAwait(false);

            // assert
            var clientSummaries = await httpClient.GetClientSummariesAsync().ConfigureAwait(false);
            clientSummaries.Should().NotBeNull();
            clientSummaries.Should().NotContain(summary => summary.Id == client.Id);
        }

        [Fact]
        public async Task CanUseClientCredentialsClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanUseClientCredentialsClient)} (integration test)",
                Secret = "secret",
                AllowedScopes = { "sample_api" },
                AllowedGrantTypes = { "client_credentials" },
            };

            await httpClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            var tokenClient = new TokenClient(this.Authority + "/connect/token", client.Id, client.Secret);
            var response = await tokenClient.RequestClientCredentialsAsync("sample_api").ConfigureAwait(false);

            // assert
            response.IsError.Should().BeFalse();
        }

        [Fact]
        public async Task CanUseImplicitClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanUseImplicitClient)} (integration test)",
                AllowedCorsOrigins = { "http://localhost:5006" },
                RedirectUris = { "http://localhost:5006/redirect" },
                AllowedScopes = { "openid", "profile", "sample_api" },
                AllowAccessTokensViaBrowser = true,
                AllowedGrantTypes = { "implicit" },
                RequireConsent = false,
            };

            await httpClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            var url = new RequestUrl(this.Authority + "/connect/authorize")
                .CreateAuthorizeUrl(client.Id, "id_token token", "openid profile sample_api", client.RedirectUris.First(), "state", "nonce");

            var automation = new BrowserAutomation(TestConfig.DefaultAdminUserEmail, TestConfig.DefaultPassword);
            await automation.NavigateToLoginAsync(url).ConfigureAwait(false);
            var authorizeResponse = await automation.LoginToAuthorizationServerAndCaptureRedirectAsync().ConfigureAwait(false);

            // assert
            authorizeResponse.IsError.Should().BeFalse();
        }

        [Fact]
        public async Task CanUseHybridClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CanUseHybridClient)} (integration test)",
                RequireClientSecret = false,
                AllowedGrantTypes = { "hybrid" },
                RequirePkce = true,
                RedirectUris = { "http://127.0.0.1" },
                AllowOfflineAccess = true,
                AllowedScopes = { "openid", "profile", "sample_api" },
                RequireConsent = false,
            };

            await httpClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            var automation = new BrowserAutomation(TestConfig.DefaultAdminUserEmail, TestConfig.DefaultPassword);
            var browser = new Browser(automation);
            var options = new OidcClientOptions
            {
                Authority = this.Authority,
                ClientId = client.Id,
                RedirectUri = $"http://127.0.0.1:{browser.Port}",
                Scope = "openid profile sample_api offline_access",
                FilterClaims = false,
                Browser = browser,
                Policy = new Policy { Discovery = new DiscoveryPolicy { ValidateIssuerName = false } }
            };

            var oidcClient = new OidcClient(options);
            var result = await oidcClient.LoginAsync(new LoginRequest()).ConfigureAwait(false);

            // assert
            result.IsError.Should().BeFalse();
        }

        [Fact]
        public void CannotAddInvalidClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                AccessTokenType = "Nonsense",
            };

            // act
            Func<Task> func = async () => await httpClient.AddClientAsync(client).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CannotAddDuplicateClient()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client = new Client
            {
                Id = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Name = $"{nameof(ClientManagement)}.{nameof(this.CannotAddDuplicateClient)} (integration test)",
            };

            await httpClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await httpClient.AddClientAsync(client).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        [Fact]
        public void CannotModifyAuthorizationServerManagementConsole()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var client = new Client
            {
                Id = "auth_console",
                AllowedScopes = { "openid" },
            };

            // act
            Func<Task> func = async () => await httpClient.ModifyClientAsync(client).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public void CannotRemoveAuthorizationServerManagementConsole()
        {
            // arrange
            var httpClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            var clientId = "auth_console";

            // act
            Func<Task> func = async () => await httpClient.RemoveClientAsync(clientId).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }
    }
}
