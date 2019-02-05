// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Integration
{
    using System;
    using System.Net;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Client;
    using Sdk;
    using Xunit;

    public class RoleManagement : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private const string RolePrefix = "role-test";

        public RoleManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task CanAddRole()
        {
            // arrange
            var role = GetRoleName();

            // act
            await _fixture.RolesClient.AddRoleAsync(role).ConfigureAwait(false);

            // assert
            var roleExists = await _fixture.RolesClient.RoleExistsAsync(role).ConfigureAwait(false);
            roleExists.Should().BeTrue();
        }

        [Fact]
        public async Task CanGetRoleSummaries()
        {
            // arrange
            var role = GetRoleName();

            await _fixture.RolesClient.AddRoleAsync(role).ConfigureAwait(false);

            // act
            var roles = await _fixture.RolesClient.GetRolesAsync().ConfigureAwait(false);

            // assert
            roles.Should().NotBeNull();
            roles.Should().Contain(role);
        }

        [Fact]
        public async Task CanGetRoleSummariesWithQuery()
        {
            // arrange
            var role1 = $"{RolePrefix}_test";
            var role2 = $"{RolePrefix}_test_02";
            var role3 = $"{RolePrefix}_test_03";

            await _fixture.RolesClient.AddRoleAsync(role1).ConfigureAwait(false);
            await _fixture.RolesClient.AddRoleAsync(role2).ConfigureAwait(false);
            await _fixture.RolesClient.AddRoleAsync(role3).ConfigureAwait(false);

            // act
            var roles = await _fixture.RolesClient.GetRolesAsync($"{RolePrefix}_test_").ConfigureAwait(false);

            // assert
            roles.Should().NotBeNull();
            roles.Should().HaveCount(2);
            roles.Should().Contain(new[] { role2, role3 });
        }

        [Fact]
        public async Task CanRemoveRole()
        {
            // arrange
            var role = GetRoleName();

            await _fixture.RolesClient.AddRoleAsync(role).ConfigureAwait(false);

            // act
            await _fixture.RolesClient.RemoveRoleAsync(role).ConfigureAwait(false);

            // assert
            var roles = await _fixture.RolesClient.GetRolesAsync().ConfigureAwait(false);
            roles.Should().NotBeNull();
            roles.Should().NotContain(role);
        }

        [Fact]
        public async Task CannotAddDuplicateRole()
        {
            // arrange
            var role = GetRoleName();

            await _fixture.RolesClient.AddRoleAsync(role).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await _fixture.RolesClient.AddRoleAsync(role).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        [Fact]
        public void CannotRemoveAdminRole()
        {
            // arrange
            var role = "admin";

            // act
            Func<Task> func = async () => await _fixture.RolesClient.RemoveRoleAsync(role).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        public void Dispose()
        {
            ResourceSet<string> roles = _fixture.RolesClient.GetRolesAsync(RolePrefix).GetAwaiter().GetResult();

            foreach (string role in roles)
            {
                _fixture.RolesClient.RemoveRoleAsync(role).GetAwaiter().GetResult();
            }
        }

        private static string GetRoleName() => $"{RolePrefix}-{Guid.NewGuid():N}";
    }
}
