// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Feature
{
    using System;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using FluentAssertions;
    using IdentityModel;
    using IdentityModel.Client;
    using Client;
    using Sdk;
    using Newtonsoft.Json.Linq;
    using Xbehave;

    public class GettingCustomClaimsFeature : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private readonly string _email;
        private readonly string _clientId;
        private const string IdentityResourceName = "amazeballs";
        private const string ApiResourceName = "amazeballs_api";

        public GettingCustomClaimsFeature(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
            _email = $"{TestConfig.EmailPrefix}{Guid.NewGuid():N}@test.com";
            _clientId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        }

        [Scenario]
        public void CanGetCustomClaims(User user, Client client, AuthorizationResponse response)
        {
            "Given the new scope is added to the authorization server"
                .x(async () => await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(
                    new IdentityResource
                    {
                        Enabled = true,
                        Name = IdentityResourceName,
                        DisplayName = "Something something amazing",
                        UserClaims = { "amaze", "balls" }
                    }).ConfigureAwait(false));

            "And an end-user is added to the authorization server _with claim values matching the new scope_"
                .x(async () => await _fixture.UsersClient.AddUserAsync(
                    user = new User
                    {
                        Username = _email,
                        Email = _email,
                        Password = "password",
                        PhoneNumber = "+123",
                        Claims = { { "amaze", "yes" }, { "balls", "no" } },
                    }).ConfigureAwait(false));

            "And an API that requires the claims from the new scope"
                .x(async () => await _fixture.ApiResourcesClient.AddApiResourceAsync(
                    new ApiResource
                    {
                        Name = ApiResourceName,
                        ApiSecret = "secret",
                        DisplayName = "Amazeballs API",
                        UserClaims = { "name", "phone_number", "amaze", "balls" },

                        // NOTE (Cameron): OMG wat?
                        // LINK (Cameron): https://github.com/IdentityServer/IdentityServer4/blob/2.1.1/src/IdentityServer4/Models/ApiResource.cs#L67
                        ApiScopes = { new ApiResource.Scope { Name = ApiResourceName, UserClaims = { "name", "phone_number", "amaze", "balls" } } },

                        Enabled = true
                    }).ConfigureAwait(false));

            "And a client for that API"
                .x(async () => await _fixture.ClientsClient.AddClientAsync(
                    client = new Client
                    {
                        Id = _clientId,
                        Name = $"{nameof(GettingCustomClaimsFeature)}.{nameof(CanGetCustomClaims)} (integration test)",
                        AllowedCorsOrigins = { "http://localhost:5006" },
                        RedirectUris = { "http://localhost:5006/redirect" },
                        AllowedScopes = { "openid", ApiResourceName },
                        AllowAccessTokensViaBrowser = true,
                        AllowedGrantTypes = { "implicit" },
                        RequireConsent = false,
                        Enabled = true
                    }).ConfigureAwait(false));

            "When that end-user logs into the authorization server via the client requesting access to the API"
                .x(async (context) =>
                {
                    var url = new RequestUrl(Authority + "/connect/authorize")
                        .CreateAuthorizeUrl(client.Id, "id_token token", $"openid {ApiResourceName}", client.RedirectUris.First(), "state", "nonce");
                    var automation = new BrowserAutomation(user.Username, user.Password).Using(context);
                    await automation.NavigateToLoginAsync(url).ConfigureAwait(false);
                    response = await automation.LoginToAuthorizationServerAndCaptureRedirectAsync().ConfigureAwait(false);
                });

            "Then that end-user is authorized to call the API"
                .x(() =>
                {
                    response.IsError.Should().BeFalse();

                    var jwtComponents = response.AccessToken.Split(".", StringSplitOptions.RemoveEmptyEntries);
                    var bytes = Base64Url.Decode(jwtComponents[1]);
                    var json = Encoding.UTF8.GetString(bytes);
                    var claims = JObject.Parse(json);

                    claims.GetValue("phone_number").ToString().Should().Be(user.PhoneNumber);
                    claims.GetValue("amaze").ToString().Should().Be("yes");
                    claims.GetValue("balls").ToString().Should().Be("no");
                });
        }

        public void Dispose()
        {
            _fixture.IdentityResourcesClient.RemoveIdentityResourceAsync(IdentityResourceName).GetAwaiter().GetResult();
            _fixture.ApiResourcesClient.RemoveApiResourceAsync(ApiResourceName).GetAwaiter().GetResult();
            _fixture.ClientsClient.RemoveClientAsync(_clientId).GetAwaiter().GetResult();
            _fixture.UsersClient.RemoveUserAsync(_email).GetAwaiter().GetResult();
        }
    }
}
