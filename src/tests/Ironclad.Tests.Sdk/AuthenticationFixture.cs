// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

#pragma warning disable SA1600, CS1591, CA1056 // not required for this class

namespace Ironclad.Tests.Sdk
{
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading;
    using System.Threading.Tasks;
    using IdentityModel.Client;
    using IdentityModel.OidcClient;
    using Ironclad.Client;
    using Xunit;
    using Xunit.Abstractions;

    public class AuthenticationFixture : IAsyncLifetime
    {
        private readonly IroncladFixture fixture;

        public AuthenticationFixture(IMessageSink messageSink = default)
        {
            // NOTE (Cameron):
            // The internally scoped Ironclad fixture manages the spinning up and tearing down of Ironclad and it's dependencies (postgres).
            // The publicly scoped authentication fixture is responsible for its lifetime which is why it is included here.
            this.fixture = new IroncladFixture(messageSink);
        }

        public string Authority => this.fixture.Authority;

        public string ApiUri => this.fixture.ApiUri;

        public IApiResourcesClient ApiResourcesClient { get; private set; }

        public IClientsClient ClientsClient { get; private set; }

        public IIdentityProvidersClient IdentityProvidersClient { get; private set; }

        public IIdentityResourcesClient IdentityResourcesClient { get; private set; }

        public IRolesClient RolesClient { get; private set; }

        public IUsersClient UsersClient { get; private set; }

        public HttpMessageHandler Handler { get; private set; }

        public async Task InitializeAsync()
        {
            await this.fixture.InitializeAsync().ConfigureAwait(false);

            // NOTE (Cameron): This automation is designed to use the default admin credentials (which need removing!) to log in to perform admin operations.
            var automation = new BrowserAutomation(TestConfig.DefaultAdminUserEmail, TestConfig.DefaultPassword);
            var browser = new Browser(automation);
            var options = new OidcClientOptions
            {
                Authority = this.Authority,
                ClientId = "auth_console",
                RedirectUri = $"http://127.0.0.1:{browser.Port}",
                Scope = "openid profile auth_api",
                FilterClaims = false,
                Browser = browser,
                Policy = new Policy { Discovery = new DiscoveryPolicy { ValidateIssuerName = false } }
            };

            var oidcClient = new OidcClient(options);
            var result = await oidcClient.LoginAsync(new LoginRequest()).ConfigureAwait(false);
            if (result.IsError)
            {
                throw new Exception(result.Error);
            }

            this.Handler = new TokenHandler(result.AccessToken);

            this.ApiResourcesClient = new ApiResourcesHttpClient(this.ApiUri, this.Handler);
            this.ClientsClient = new ClientsHttpClient(this.ApiUri, this.Handler);
            this.IdentityProvidersClient = new IdentityProvidersHttpClient(this.ApiUri, this.Handler);
            this.IdentityResourcesClient = new IdentityResourcesHttpClient(this.ApiUri, this.Handler);
            this.RolesClient = new RolesHttpClient(this.ApiUri, this.Handler);
            this.UsersClient = new UsersHttpClient(this.ApiUri, this.Handler);

            await this.OnInitializeAsync().ConfigureAwait(false);
        }

        public async Task DisposeAsync()
        {
            await this.OnDisposeAsync().ConfigureAwait(false);

            (this.ApiResourcesClient as IDisposable)?.Dispose();
            (this.ClientsClient as IDisposable)?.Dispose();
            (this.IdentityProvidersClient as IDisposable)?.Dispose();
            (this.IdentityResourcesClient as IDisposable)?.Dispose();
            (this.RolesClient as IDisposable)?.Dispose();
            (this.UsersClient as IDisposable)?.Dispose();

            this.Handler?.Dispose();

            await this.fixture.DisposeAsync().ConfigureAwait(false);
        }

        protected virtual Task OnInitializeAsync() => Task.CompletedTask;

        protected virtual Task OnDisposeAsync() => Task.CompletedTask;

        private sealed class WaitUntilAvailableResult
        {
            public static readonly WaitUntilAvailableResult NotAvailable = new WaitUntilAvailableResult(null);

            private WaitUntilAvailableResult(string accessToken)
            {
                this.AccessToken = accessToken;
            }

            public string AccessToken { get; }

            public static WaitUntilAvailableResult Available(string accessToken) => new WaitUntilAvailableResult(accessToken);
        }

        private sealed class TokenHandler : DelegatingHandler
        {
            private readonly string accessToken;

            public TokenHandler(string accessToken)
                : base(new HttpClientHandler())
            {
                this.accessToken = accessToken;
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", this.accessToken);
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
