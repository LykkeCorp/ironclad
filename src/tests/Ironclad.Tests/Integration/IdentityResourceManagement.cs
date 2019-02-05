// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Integration
{
    using System;
    using System.Globalization;
    using System.Net;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Client;
    using Sdk;
    using Xunit;

    public class IdentityResourceManagement : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private const string IdentityResourcePrefix = "idres-test";

        public IdentityResourceManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task CanAddIdentityResourceMinimum()
        {
            // arrange
            var expectedResource = new IdentityResource
            {
                Name = GetResourceName(),
                UserClaims = { "role" },
            };

            // act
            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(expectedResource).ConfigureAwait(false);

            // assert
            var actualResource = await _fixture.IdentityResourcesClient.GetIdentityResourceAsync(expectedResource.Name).ConfigureAwait(false);
            actualResource.Should().NotBeNull();
            actualResource.Name.Should().Be(expectedResource.Name);
            actualResource.UserClaims.Should().Contain(expectedResource.UserClaims);
        }

        [Fact]
        public async Task CanAddIdentityResource()
        {
            // arrange
            var expectedResource = new IdentityResource
            {
                Name = GetResourceName(),
                DisplayName = $"{nameof(IdentityResourceManagement)}.{nameof(CanAddIdentityResource)} (integration test)",
                UserClaims = { "name", "role" },
                Enabled = false,
            };

            // act
            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(expectedResource).ConfigureAwait(false);

            // assert
            var actualResource = await _fixture.IdentityResourcesClient.GetIdentityResourceAsync(expectedResource.Name).ConfigureAwait(false);
            actualResource.Should().NotBeNull();
            actualResource.Should().BeEquivalentTo(expectedResource);
        }

        [Fact]
        public async Task CanGetIdentityResourceSummaries()
        {
            // arrange
            var expectedResource = new IdentityResource
            {
                Name = GetResourceName(),
                DisplayName = $"{nameof(IdentityResourceManagement)}.{nameof(CanGetIdentityResourceSummaries)} (integration test)",
                UserClaims = { "role" },
            };

            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(expectedResource).ConfigureAwait(false);

            // act
            var resourceSummaries = await _fixture.IdentityResourcesClient.GetIdentityResourceSummariesAsync().ConfigureAwait(false);

            // assert
            resourceSummaries.Should().NotBeNull();
            resourceSummaries.Should().Contain(summary => summary.Name == expectedResource.Name && summary.DisplayName == expectedResource.DisplayName);
        }

        [Fact]
        public async Task CanGetIdentityResourceSummariesWithQuery()
        {
            // arrange
            var resource1 = new IdentityResource { Name = $"{IdentityResourcePrefix}_test", UserClaims = { "name" } };
            var resource2 = new IdentityResource { Name = $"{IdentityResourcePrefix}_test_02", UserClaims = { "name" } };
            var resource3 = new IdentityResource { Name = $"{IdentityResourcePrefix}_test_03", UserClaims = { "name" } };

            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(resource1).ConfigureAwait(false);
            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(resource2).ConfigureAwait(false);
            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(resource3).ConfigureAwait(false);

            // act
            var resourceSummaries = await _fixture.IdentityResourcesClient.GetIdentityResourceSummariesAsync($"{IdentityResourcePrefix}_test_").ConfigureAwait(false);

            // assert
            resourceSummaries.Should().NotBeNull();
            resourceSummaries.Should().HaveCount(2);
            resourceSummaries.Should().Contain(summary => summary.Name == resource2.Name);
            resourceSummaries.Should().Contain(summary => summary.Name == resource3.Name);
        }

        [Fact]
        public async Task CanModifyIdentityResource()
        {
            // arrange
            var originalIdentityResource = new IdentityResource
            {
                Name = GetResourceName(),
                DisplayName = $"{nameof(IdentityResourceManagement)}.{nameof(CanModifyIdentityResource)} (integration test)",
                UserClaims = { "name", "role" },
                Enabled = false,
            };

            var expectedResource = new IdentityResource
            {
                Name = originalIdentityResource.Name,
                DisplayName = $"{nameof(IdentityResourceManagement)}.{nameof(CanModifyIdentityResource)} (integration test) #2",
                UserClaims = { "profile" },
                Enabled = false,
            };

            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(originalIdentityResource).ConfigureAwait(false);

            // act
            await _fixture.IdentityResourcesClient.ModifyIdentityResourceAsync(expectedResource).ConfigureAwait(false);

            // assert
            var actualResource = await _fixture.IdentityResourcesClient.GetIdentityResourceAsync(expectedResource.Name).ConfigureAwait(false);
            actualResource.Should().NotBeNull();
            actualResource.Should().BeEquivalentTo(expectedResource);
        }

        [Fact]
        public async Task CanRemoveIdentityResource()
        {
            // arrange
            var resource = new IdentityResource
            {
                Name = GetResourceName(),
                DisplayName = $"{nameof(IdentityResourceManagement)}.{nameof(CanRemoveIdentityResource)} (integration test)",
                UserClaims = { "role" },
            };

            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(resource).ConfigureAwait(false);

            // act
            await _fixture.IdentityResourcesClient.RemoveIdentityResourceAsync(resource.Name).ConfigureAwait(false);

            // assert
            var resourceSummaries = await _fixture.IdentityResourcesClient.GetIdentityResourceSummariesAsync().ConfigureAwait(false);
            resourceSummaries.Should().NotBeNull();
            resourceSummaries.Should().NotContain(summary => summary.Name == resource.Name);
        }

        [Fact]
        public void CannotAddInvalidIdentityResource()
        {
            // arrange
            var resource = new IdentityResource
            {
                Name = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                DisplayName = $"{nameof(IdentityResourceManagement)}.{nameof(CannotAddInvalidIdentityResource)} (integration test)",
            };

            // act
            Func<Task> func = async () => await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(resource).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CannotAddDuplicateIdentityResource()
        {
            // arrange
            var resource = new IdentityResource
            {
                Name = GetResourceName(),
                DisplayName = $"{nameof(IdentityResourceManagement)}.{nameof(CannotAddDuplicateIdentityResource)} (integration test)",
                UserClaims = { "role" },
            };

            await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(resource).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await _fixture.IdentityResourcesClient.AddIdentityResourceAsync(resource).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        public void Dispose()
        {
            var resources = _fixture.IdentityResourcesClient
                .GetIdentityResourceSummariesAsync(IdentityResourcePrefix)
                .GetAwaiter().GetResult();

            foreach (var resource in resources)
            {
                _fixture.IdentityResourcesClient.RemoveIdentityResourceAsync(resource.Name).GetAwaiter().GetResult();
            }
        }

        private static string GetResourceName() => $"{IdentityResourcePrefix}-{Guid.NewGuid():N}";
    }
}
