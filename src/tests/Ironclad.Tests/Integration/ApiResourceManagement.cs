// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Integration
{
    using System;
    using System.Net;
    using System.Threading.Tasks;
    using FluentAssertions;
    using IdentityModel.Client;
    using Client;
    using Sdk;
    using Xunit;

    public class ApiResourceManagement : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private const string ApiResourcePrefix = "ar-test";

        public ApiResourceManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task CanAddApiResourceMinimum()
        {
            // arrange
            var expectedResource = new ApiResource
            {
                Name = GetApiResourceName(),
                ApiSecret = "secret",
            };

            // act
            await _fixture.ApiResourcesClient.AddApiResourceAsync(expectedResource).ConfigureAwait(false);

            // assert
            var actualResource = await _fixture.ApiResourcesClient.GetApiResourceAsync(expectedResource.Name).ConfigureAwait(false);
            actualResource.Should().NotBeNull();
            actualResource.Name.Should().Be(expectedResource.Name);
        }

        [Fact]
        public async Task CanAddApiResource()
        {
            // arrange
            var expectedResource = new ApiResource
            {
                Name = GetApiResourceName(),
                DisplayName = $"{nameof(ApiResourceManagement)}.{nameof(CanAddApiResource)} (integration test)",
                ApiSecret = "secret",
                UserClaims = { "name", "role" },
                ApiScopes = { new ApiResource.Scope { Name = "api", UserClaims = { "profile" } } },
                Enabled = false,
            };

            // act
            await _fixture.ApiResourcesClient.AddApiResourceAsync(expectedResource).ConfigureAwait(false);

            // assert
            var actualResource = await _fixture.ApiResourcesClient.GetApiResourceAsync(expectedResource.Name).ConfigureAwait(false);
            actualResource.Should().NotBeNull();
            actualResource.Should().BeEquivalentTo(expectedResource, options => options.Excluding(resource => resource.ApiSecret));
        }

        [Fact]
        public async Task CanGetApiResourceSummaries()
        {
            // arrange
            var expectedResource = new ApiResource
            {
                Name = GetApiResourceName(),
                DisplayName = $"{nameof(ApiResourceManagement)}.{nameof(CanGetApiResourceSummaries)} (integration test)",
                ApiSecret = "secret",
            };

            await _fixture.ApiResourcesClient.AddApiResourceAsync(expectedResource).ConfigureAwait(false);

            // act
            var resourceSummaries = await _fixture.ApiResourcesClient.GetApiResourceSummariesAsync().ConfigureAwait(false);

            // assert
            resourceSummaries.Should().NotBeNull();
            resourceSummaries.Should().Contain(summary => summary.Name == expectedResource.Name && summary.DisplayName == expectedResource.DisplayName);
        }

        [Fact]
        public async Task CanGetApiResourceSummariesWithQuery()
        {
            // arrange
            var resource1 = new ApiResource { Name = $"{ApiResourcePrefix}_test", ApiSecret = "secret" };
            var resource2 = new ApiResource { Name = $"{ApiResourcePrefix}_test_02", ApiSecret = "secret" };
            var resource3 = new ApiResource { Name = $"{ApiResourcePrefix}_test_03", ApiSecret = "secret" };

            await _fixture.ApiResourcesClient.AddApiResourceAsync(resource1).ConfigureAwait(false);
            await _fixture.ApiResourcesClient.AddApiResourceAsync(resource2).ConfigureAwait(false);
            await _fixture.ApiResourcesClient.AddApiResourceAsync(resource3).ConfigureAwait(false);

            // act
            var resourceSummaries = await _fixture.ApiResourcesClient.GetApiResourceSummariesAsync($"{ApiResourcePrefix}_test_").ConfigureAwait(false);

            // assert
            resourceSummaries.Should().NotBeNull();
            resourceSummaries.Should().HaveCount(2);
            resourceSummaries.Should().Contain(summary => summary.Name == resource2.Name);
            resourceSummaries.Should().Contain(summary => summary.Name == resource3.Name);
        }

        [Fact]
        public async Task CanModifyApiResource()
        {
            // arrange
            var originalApiResource = new ApiResource
            {
                Name = GetApiResourceName(),
                DisplayName = $"{nameof(ApiResourceManagement)}.{nameof(CanModifyApiResource)} (integration test)",
                ApiSecret = "secret",
                UserClaims = { "name", "role" },
                ApiScopes = { new ApiResource.Scope { Name = "api", UserClaims = { "profile" } } },
                Enabled = false,
            };

            var expectedResource = new ApiResource
            {
                Name = originalApiResource.Name,
                DisplayName = $"{nameof(ApiResourceManagement)}.{nameof(CanModifyApiResource)} (integration test) #2",
                UserClaims = { "profile" },
                ApiScopes = { new ApiResource.Scope { Name = "test_api", UserClaims = { "name", "role" } } },
                Enabled = true,
            };

            await _fixture.ApiResourcesClient.AddApiResourceAsync(originalApiResource).ConfigureAwait(false);

            // act
            await _fixture.ApiResourcesClient.ModifyApiResourceAsync(expectedResource).ConfigureAwait(false);

            // assert
            var actualResource = await _fixture.ApiResourcesClient.GetApiResourceAsync(expectedResource.Name).ConfigureAwait(false);
            actualResource.Should().NotBeNull();
            actualResource.Should().BeEquivalentTo(expectedResource, options => options.Excluding(resource => resource.ApiSecret));
        }

        [Fact]
        public async Task CanRemoveApiResource()
        {
            // arrange
            var resource = new ApiResource
            {
                Name = GetApiResourceName(),
                DisplayName = $"{nameof(ApiResourceManagement)}.{nameof(CanRemoveApiResource)} (integration test)",
                ApiSecret = "secret",
            };

            await _fixture.ApiResourcesClient.AddApiResourceAsync(resource).ConfigureAwait(false);

            // act
            await _fixture.ApiResourcesClient.RemoveApiResourceAsync(resource.Name).ConfigureAwait(false);

            // assert
            var resourceSummaries = await _fixture.ApiResourcesClient.GetApiResourceSummariesAsync().ConfigureAwait(false);
            resourceSummaries.Should().NotBeNull();
            resourceSummaries.Should().NotContain(summary => summary.Name == resource.Name);
        }

        // LINK (Cameron): https://github.com/IdentityServer/IdentityServer4.AccessTokenValidation/blob/dev/src/IdentityServer4.AccessTokenValidation/IdentityServerAuthenticationOptions.cs#L231
        [Fact]
        public async Task CanUseApiResource()
        {
            // arrange
            var resource = new ApiResource
            {
                Name = GetApiResourceName(),
                ApiSecret = "secret",
            };

            await _fixture.ApiResourcesClient.AddApiResourceAsync(resource).ConfigureAwait(false);

            // act
            var client = new IntrospectionClient(Authority + "/connect/introspect", resource.Name, resource.ApiSecret);
            var response = await client.SendAsync(new IntrospectionRequest { Token = "invalid" }).ConfigureAwait(false);

            // assert
            response.IsError.Should().BeFalse();
        }

        [Fact]
        public void CannotAddInvalidApiResource()
        {
            // arrange
            var resource = new ApiResource
            {
                Name = GetApiResourceName()
            };

            // act
            Func<Task> func = async () => await _fixture.ApiResourcesClient.AddApiResourceAsync(resource).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CannotAddDuplicateApiResource()
        {
            // arrange
            var resource = new ApiResource
            {
                Name = GetApiResourceName(),
                DisplayName = $"{nameof(ApiResourceManagement)}.{nameof(CannotAddDuplicateApiResource)} (integration test)",
                ApiSecret = "secret",
            };

            await _fixture.ApiResourcesClient.AddApiResourceAsync(resource).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await _fixture.ApiResourcesClient.AddApiResourceAsync(resource).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        [Fact]
        public void CannotModifyAuthorizationServerWebApi()
        {
            // arrange
            var resource = new ApiResource
            {
                Name = "auth_api",
                UserClaims = Array.Empty<string>(),
            };

            // act
            Func<Task> func = async () => await _fixture.ApiResourcesClient.ModifyApiResourceAsync(resource).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public void CannotRemoveAuthorizationServerWebApi()
        {
            // arrange
            var resourceName = "auth_api";

            // act
            Func<Task> func = async () => await _fixture.ApiResourcesClient.RemoveApiResourceAsync(resourceName).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        public void Dispose()
        {
            ResourceSet<ResourceSummary> resources = _fixture.ApiResourcesClient.GetApiResourceSummariesAsync(ApiResourcePrefix).GetAwaiter().GetResult();

            foreach (var resource in resources)
            {
                _fixture.ApiResourcesClient.RemoveApiResourceAsync(resource.Name).GetAwaiter().GetResult();
            }
        }

        private static string GetApiResourceName() => $"{ApiResourcePrefix}-{Guid.NewGuid():N}";
    }
}
