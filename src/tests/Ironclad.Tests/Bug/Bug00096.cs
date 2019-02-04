// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.
namespace Ironclad.Tests.Bug
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Client;
    using Sdk;
    using Xunit;

    public class Bug00096 : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private const string ScopeName = "scope_name";

        public Bug00096(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task ShouldCreateApiResourceWithDefaultScopeMatchingResourceName()
        {
            // arrange
            var expectedResource = new ApiResource
            {
                Name = ScopeName,
                ApiSecret = "secret",
                ApiScopes = null, // should default to "scope_name"
            };

            // act
            await _fixture.ApiResourcesClient.AddApiResourceAsync(expectedResource).ConfigureAwait(false);

            // assert
            var actualResource = await _fixture.ApiResourcesClient.GetApiResourceAsync(expectedResource.Name).ConfigureAwait(false);
            actualResource.Should().NotBeNull();
            actualResource.ApiScopes.Should().HaveCount(1);
            actualResource.ApiScopes.First().Name.Should().Be(expectedResource.Name);
        }

        public void Dispose()
        {
            _fixture.ApiResourcesClient.RemoveApiResourceAsync(ScopeName).GetAwaiter().GetResult();
        }
    }
}
