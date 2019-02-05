// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Integration
{
    using System;
    using System.Linq;
    using System.Net;
    using System.Threading.Tasks;
    using FluentAssertions;
    using IdentityModel.Client;
    using IdentityModel.OidcClient;
    using Client;
    using Sdk;
    using Xunit;

    public class ClientManagement : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private const string ApiClientPrefix = "client-test";

        public ClientManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task CanAddClientMinimum()
        {
            // arrange
            var expectedClient = new Client
            {
                Id = GetClientId()
            };

            // act
            await _fixture.ClientsClient.AddClientAsync(expectedClient).ConfigureAwait(false);

            // assert
            var actualClient = await _fixture.ClientsClient.GetClientAsync(expectedClient.Id).ConfigureAwait(false);
            actualClient.Should().NotBeNull();
            actualClient.Id.Should().Be(expectedClient.Id);
        }

        [Fact]
        public async Task CanAddClient()
        {
            // arrange
            var expectedClient = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CanAddClient)} (integration test)",
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
            await _fixture.ClientsClient.AddClientAsync(expectedClient).ConfigureAwait(false);

            // assert
            var actualClient = await _fixture.ClientsClient.GetClientAsync(expectedClient.Id).ConfigureAwait(false);
            actualClient.Should().NotBeNull();
            actualClient.Should().BeEquivalentTo(expectedClient, options => options.Excluding(client => client.Secret));
        }

        [Fact]
        public async Task CanGetClientSummaries()
        {
            // arrange
            var expectedClient = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CanGetClientSummaries)} (integration test)",
            };

            await _fixture.ClientsClient.AddClientAsync(expectedClient).ConfigureAwait(false);

            // act
            var clientSummaries = await _fixture.ClientsClient.GetClientSummariesAsync().ConfigureAwait(false);

            // assert
            clientSummaries.Should().NotBeNull();
            clientSummaries.Should().Contain(summary => summary.Id == expectedClient.Id && summary.Name == expectedClient.Name);
        }

        [Fact]
        public async Task CanGetClientSummariesWithQuery()
        {
            // arrange
            var client1 = new Client { Id = $"{ApiClientPrefix}_test" };
            var client2 = new Client { Id = $"{ApiClientPrefix}_test_02" };
            var client3 = new Client { Id = $"{ApiClientPrefix}_test_03" };

            await _fixture.ClientsClient.AddClientAsync(client1).ConfigureAwait(false);
            await _fixture.ClientsClient.AddClientAsync(client2).ConfigureAwait(false);
            await _fixture.ClientsClient.AddClientAsync(client3).ConfigureAwait(false);

            // act
            var clientSummaries = await _fixture.ClientsClient.GetClientSummariesAsync($"{ApiClientPrefix}_test_").ConfigureAwait(false);

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
            var originalClient = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CanModifyClient)} (integration test)",
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
                Name = $"{nameof(ClientManagement)}.{nameof(CanModifyClient)} (integration test) #2",
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

            await _fixture.ClientsClient.AddClientAsync(originalClient).ConfigureAwait(false);

            // act
            await _fixture.ClientsClient.ModifyClientAsync(expectedClient).ConfigureAwait(false);

            // assert
            var actualClient = await _fixture.ClientsClient.GetClientAsync(expectedClient.Id).ConfigureAwait(false);
            actualClient.Should().NotBeNull();
            actualClient.Should().BeEquivalentTo(expectedClient, options => options.Excluding(client => client.Secret));
        }

        [Fact]
        public async Task CanRemoveClient()
        {
            // arrange
            var client = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CanRemoveClient)} (integration test)",
            };

            await _fixture.ClientsClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            await _fixture.ClientsClient.RemoveClientAsync(client.Id).ConfigureAwait(false);

            // assert
            var clientSummaries = await _fixture.ClientsClient.GetClientSummariesAsync().ConfigureAwait(false);
            clientSummaries.Should().NotBeNull();
            clientSummaries.Should().NotContain(summary => summary.Id == client.Id);
        }

        [Fact]
        public async Task CanUseClientCredentialsClient()
        {
            // arrange
            var client = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CanUseClientCredentialsClient)} (integration test)",
                Secret = "secret",
                AllowedScopes = { "sample_api" },
                AllowedGrantTypes = { "client_credentials" },
            };

            await _fixture.ClientsClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            var tokenClient = new TokenClient(Authority + "/connect/token", client.Id, client.Secret);
            var response = await tokenClient.RequestClientCredentialsAsync("sample_api").ConfigureAwait(false);

            // assert
            response.IsError.Should().BeFalse();
        }

        [Fact]
        public async Task CanUseImplicitClient()
        {
            // arrange
            var client = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CanUseImplicitClient)} (integration test)",
                AllowedCorsOrigins = { "http://localhost:5006" },
                RedirectUris = { "http://localhost:5006/redirect" },
                AllowedScopes = { "openid", "profile", "sample_api" },
                AllowAccessTokensViaBrowser = true,
                AllowedGrantTypes = { "implicit" },
                RequireConsent = false,
            };

            await _fixture.ClientsClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            var url = new RequestUrl(Authority + "/connect/authorize")
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
            var client = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CanUseHybridClient)} (integration test)",
                RequireClientSecret = false,
                AllowedGrantTypes = { "hybrid" },
                RequirePkce = true,
                RedirectUris = { "http://127.0.0.1" },
                AllowOfflineAccess = true,
                AllowedScopes = { "openid", "profile", "sample_api" },
                RequireConsent = false,
            };

            await _fixture.ClientsClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            var automation = new BrowserAutomation(TestConfig.DefaultAdminUserEmail, TestConfig.DefaultPassword);
            var browser = new Browser(automation);
            var options = new OidcClientOptions
            {
                Authority = Authority,
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
            var client = new Client
            {
                Id = GetClientId(),
                AccessTokenType = "Nonsense",
            };

            // act
            Func<Task> func = async () => await _fixture.ClientsClient.AddClientAsync(client).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CannotAddDuplicateClient()
        {
            // arrange
            var client = new Client
            {
                Id = GetClientId(),
                Name = $"{nameof(ClientManagement)}.{nameof(CannotAddDuplicateClient)} (integration test)",
            };

            await _fixture.ClientsClient.AddClientAsync(client).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await _fixture.ClientsClient.AddClientAsync(client).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        [Fact]
        public void CannotModifyAuthorizationServerManagementConsole()
        {
            // arrange
            var client = new Client
            {
                Id = "auth_console",
                AllowedScopes = { "openid" },
            };

            // act
            Func<Task> func = async () => await _fixture.ClientsClient.ModifyClientAsync(client).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public void CannotRemoveAuthorizationServerManagementConsole()
        {
            // arrange
            var clientId = "auth_console";

            // act
            Func<Task> func = async () => await _fixture.ClientsClient.RemoveClientAsync(clientId).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        public void Dispose()
        {
            var clients = _fixture.ClientsClient.GetClientSummariesAsync(ApiClientPrefix)
                .ConfigureAwait(false).GetAwaiter().GetResult();

            foreach (var client in clients)
            {
                _fixture.ClientsClient.RemoveClientAsync(client.Id).GetAwaiter().GetResult();
            }
            
        }

        private static string GetClientId() => $"{ApiClientPrefix}-{Guid.NewGuid():N}";
    }
}
