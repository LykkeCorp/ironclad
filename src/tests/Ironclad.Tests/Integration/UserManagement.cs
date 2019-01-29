// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Integration
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Net;
    using System.Threading.Tasks;
    using FluentAssertions;
    using IdentityModel.Client;
    using IdentityModel.OidcClient;
    using Client;
    using Sdk;
    using Xunit;

    public class UserManagement : AuthenticationTest
    {
        public UserManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
        }

        [Fact]
        public async Task CanAddUserMinimum()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var expectedUser = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
            };

            // act
            var actualUser = await httpClient.AddUserAsync(expectedUser).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Username.Should().Be(expectedUser.Username);
        }

        [Fact]
        public async Task CanAddUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var expectedUser = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" } }
            };

            // act
            var actualUser = await httpClient.AddUserAsync(expectedUser).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(expectedUser, options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.Claims.Should().Contain(expectedUser.Claims);
        }

        [Fact]
        public async Task CanAddUserWithConfirmationEmail()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var expectedUser = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Email = "bit-bucket@test.smtp.org",
                SendConfirmationEmail = true,
                PhoneNumber = "123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" } }
            };

            // act
            var actualUser = await httpClient.AddUserAsync(expectedUser).ConfigureAwait(false);

            // assert
            // TODO (Cameron): Assert email was sent (somehow).
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(
                expectedUser,
                options => options
                    .Excluding(user => user.Id)
                    .Excluding(user => user.Password)
                    .Excluding(user => user.SendConfirmationEmail)
                    .Excluding(user => user.RegistrationLink)
                    .Excluding(user => user.Claims));
            actualUser.RegistrationLink.Should().NotBeNull();
        }

        [Fact]
        public async Task CanGetUserSummaries()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var expectedUser = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Email = "bit-bucket@test.smtp.org",
            };

            var actualUser = await httpClient.AddUserAsync(expectedUser).ConfigureAwait(false);

            // act
            var userSummaries = await httpClient.GetUserSummariesAsync().ConfigureAwait(false);

            // assert
            userSummaries.Should().NotBeNull();
            userSummaries.Should().Contain(summary => summary.Id == actualUser.Id && summary.Username == expectedUser.Username && summary.Email == expectedUser.Email);
        }

        [Fact]
        public async Task CanGetRoleSummariesWithQuery()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var user1 = new User { Username = "query" };
            var user2 = new User { Username = "query_test_02" };
            var user3 = new User { Username = "query_test_03" };

            await httpClient.AddUserAsync(user1).ConfigureAwait(false);
            await httpClient.AddUserAsync(user2).ConfigureAwait(false);
            await httpClient.AddUserAsync(user3).ConfigureAwait(false);

            // act
            var userSummaries = await httpClient.GetUserSummariesAsync("query_").ConfigureAwait(false);

            // assert
            userSummaries.Should().NotBeNull();
            userSummaries.Should().HaveCount(2);
            userSummaries.Should().Contain(summary => summary.Username == user2.Username);
            userSummaries.Should().Contain(summary => summary.Username == user3.Username);
        }

        [Fact]
        public async Task CanModifyUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var originalUser = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password4bob",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" }, { "claim2", "A" } },
            };

            var expectedUser = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password4superbob",
                Email = "superbob@superbob.com",
                PhoneNumber = "987654321",
                Roles = { "auth_admin", "user_admin" },
                Claims = { { "claim2", "B" }, { "claim3", "3" } },
            };

            var initialUser = await httpClient.AddUserAsync(originalUser).ConfigureAwait(false);

            // act
            var actualUser = await httpClient.ModifyUserAsync(expectedUser, originalUser.Username).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(expectedUser, options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.Claims.Should().Contain(expectedUser.Claims);
            actualUser.Claims.Should().NotContain(originalUser.Claims);
            actualUser.Id.Should().Be(initialUser.Id);
        }

        [Fact]
        public async Task CanRemoveUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var user = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
            };

            await httpClient.AddUserAsync(user).ConfigureAwait(false);

            // act
            await httpClient.RemoveUserAsync(user.Username).ConfigureAwait(false);

            // assert
            var userSummaries = await httpClient.GetUserSummariesAsync().ConfigureAwait(false);
            userSummaries.Should().NotBeNull();
            userSummaries.Should().NotContain(summary => summary.Username == user.Username);
        }

        [Fact]
        public async Task CanUseUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var user = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
            };

            var adminUser = await httpClient.GetUserAsync("admin");
            var usr = await httpClient.AddUserAsync(user).ConfigureAwait(false);

            // act
            var automation = new BrowserAutomation(user.Username, user.Password);
            var browser = new Browser(automation);
            var options = new OidcClientOptions
            {
                Authority = this.Authority,
                ClientId = "auth_console",
                RedirectUri = $"http://127.0.0.1:{browser.Port}",
                Scope = "openid profile auth_api offline_access",
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
        public void CannotAddInvalidUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var user = new User();

            // act
            Func<Task> func = async () => await httpClient.AddUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CannotAddDuplicateUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var user = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
            };

            await httpClient.AddUserAsync(user).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await httpClient.AddUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        [Fact]
        public void CannotRemoveDefaultAdminUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var username = "admin";

            // act
            Func<Task> func = async () => await httpClient.RemoveUserAsync(username).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public void CannotRemoveAdminRoleFromDefaultAdminUser()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var user = new User
            {
                Username = "admin",
                Roles = { },
            };

            // act
            Func<Task> func = async () => await httpClient.ModifyUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public void CannotAddUserWithNonExistingRole()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin", "lambo_owner" },
            };

            // act
            Func<Task> func = async () => await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CannotModifyUserRolesWithNonExistingRole()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin" },
            };

            var user = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model.Roles.Add("lambo_owner");

            Func<Task> func = async () => await httpClient.ModifyUserAsync(model).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CannotModifyUserClaimsWithInvalidClaimValues()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" } },
            };

            var user = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model.Claims = new Dictionary<string, object> { { string.Empty, null } };

            Func<Task> func = async () => await httpClient.ModifyUserAsync(model).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanRemoveUserClaims()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" }, { "claim2", "2" } },
            };

            var originalUser = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            var updateModel = new User
            {
                Username = originalUser.Username,
                Roles = null, // do *not* update roles
                Claims = { }, // *do* update claims
            };

            // act
            var actualUser = await httpClient.ModifyUserAsync(updateModel, updateModel.Username).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(originalUser, options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.Id.Should().Be(originalUser.Id);
            actualUser.Claims.Should().NotContain(model.Claims);
        }

        [Fact]
        public async Task CanRemoveUserRoles()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" }, { "claim2", "2" } },
            };

            var originalUser = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model = new User
            {
                Username = originalUser.Username,
                Roles = { }, // do *not* update roles
                Claims = null, // *do* update claims
            };

            // act
            var actualUser = await httpClient.ModifyUserAsync(model, model.Username).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(
                originalUser,
                options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Roles).Excluding(user => user.Claims));
            actualUser.Id.Should().Be(originalUser.Id);
            actualUser.Roles.Should().BeEmpty();
        }

        [Fact]
        public async Task CanAddUserToRoles()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789"
            };

            var originalUser = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await httpClient.AddRolesAsync(originalUser.Username, new[] {"admin"});

            var actualUser = await httpClient.GetUserAsync(originalUser.Username);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(originalUser,
                options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Roles));
            actualUser.Id.Should().Be(originalUser.Id);
            actualUser.Roles.Should().NotBeEmpty();
            actualUser.Roles.Should().Contain("admin");
        }

        [Fact]
        public async Task CannotAddUserToNonExistingRole()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = { "admin" }
            };

            var originalUser = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await httpClient.AddRolesAsync(originalUser.Username, new[] { "lambo_owner" }).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanRemoveUserFromRoles()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Roles = {"admin"}
            };

            var originalUser = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await httpClient.RemoveRolesAsync(originalUser.Username, new[] {"admin"});

            var actualUser = await httpClient.GetUserAsync(originalUser.Username).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(
                originalUser,
                options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Roles));
            actualUser.Id.Should().Be(originalUser.Id);
            actualUser.Roles.Should().BeEmpty();
        }

        [Fact]
        public void CannotRemoveDefaultAdminUserFromAdminRole()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);

            // act
            Func<Task> func = async () =>
                await httpClient.RemoveRolesAsync("admin", new[] {"admin"}).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanAddUserClaims()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789"
            };

            var originalUser = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await httpClient.AddClaimsAsync(originalUser.Username,
                new Dictionary<string, object>
                {
                    { "claim1", new object[] {"1", "2", "3"} },
                    { "claim2", new object[] {"21", "22", "23"} }
                });

            var actualUser = await httpClient.GetUserAsync(originalUser.Username);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(originalUser, options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.Id.Should().Be(originalUser.Id);
            actualUser.Claims.Should().NotBeEmpty();
            actualUser.Claims.Should().ContainKey("claim1");
            actualUser.Claims.Should().ContainKey("claim2");
        }

        [Fact]
        public async Task CannotAddUserClaimsWithInvalidClaimValues()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789"
            };

            var user = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model.Claims = new Dictionary<string, object> { { string.Empty, null } };

            Func<Task> func = async () =>
                await httpClient
                    .AddClaimsAsync(user.Username, new Dictionary<string, object> { {string.Empty, null} })
                    .ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanRemoveUserClaim()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            var model = new User
            {
                Username = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
                Password = "password",
                Email = "bit-bucket@test.smtp.org",
                PhoneNumber = "123456789",
                Claims = new Dictionary<string, object> { {"claim1", "1"}, {"claim2", "2"} }
            };

            var originalUser = await httpClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await httpClient.RemoveClaimsAsync(originalUser.Username, new Dictionary<string, object> { {"claim1", new List<object> {"1"} } });

            var actualUser = await httpClient.GetUserAsync(originalUser.Username);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(originalUser, options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.Id.Should().Be(originalUser.Id);
            actualUser.Claims.Should().NotBeEmpty();
            actualUser.Claims.Should().NotContainKey("claim1");
            actualUser.Claims.Should().ContainKey("claim2");
        }
    }
}
