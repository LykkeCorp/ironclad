// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Integration
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Threading.Tasks;
    using FluentAssertions;
    using IdentityModel.Client;
    using IdentityModel.OidcClient;
    using Client;
    using Sdk;
    using Xunit;

    public class UserManagement : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;

        public UserManagement(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public async Task CannotAddUserWithoutPassword()
        {
            // arrange
            string email = GetEmail();
            
            var expectedUser = new User
            {
                Username = email
            };

            // act
            Func<Task> func = async () => await _fixture.UsersClient.AddUserAsync(expectedUser).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CanAddUser()
        {
            // arrange
            string email = GetEmail();

            var expectedUser = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" } }
            };

            // act
            var actualUser = await _fixture.UsersClient.AddUserAsync(expectedUser).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(expectedUser, options => options.Excluding(user => user.Id).Excluding(user => user.FullName).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.Claims.Should().Contain(expectedUser.Claims);
        }

        [Fact(Skip = "not implemented or will be changed")]
        public async Task CanAddUserWithConfirmationEmail()
        {
            // arrange
            string email = GetEmail();
            
            var expectedUser = new User
            {
                Username = email,
                Email = email,
                SendConfirmationEmail = true,
                PhoneNumber = "+123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" } }
            };

            // act
            var actualUser = await _fixture.UsersClient.AddUserAsync(expectedUser).ConfigureAwait(false);

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
            string email = GetEmail();
            
            var expectedUser = new User
            {
                Username = email,
                Email = email,
                Password = TestConfig.DefaultPassword
            };

            var actualUser = await _fixture.UsersClient.AddUserAsync(expectedUser).ConfigureAwait(false);

            // act
            var userSummaries = await _fixture.UsersClient.GetUserSummariesAsync(TestConfig.EmailPrefix).ConfigureAwait(false);

            // assert
            userSummaries.Should().NotBeNull();
            userSummaries.Should().Contain(summary => summary.Id == actualUser.Id && summary.Username == expectedUser.Username && summary.Email == expectedUser.Email);
        }

        [Fact]
        public async Task CanGetRoleSummariesWithQuery()
        {
            // arrange
            var user1 = new User { Username = $"{TestConfig.EmailPrefix}query_test@test.com", Password = TestConfig.DefaultPassword};
            var user2 = new User { Username = $"{TestConfig.EmailPrefix}query_test_02@test.com", Password = TestConfig.DefaultPassword};
            var user3 = new User { Username = $"{TestConfig.EmailPrefix}query_test_03@test.com", Password = TestConfig.DefaultPassword};

            await _fixture.UsersClient.AddUserAsync(user1).ConfigureAwait(false);
            await _fixture.UsersClient.AddUserAsync(user2).ConfigureAwait(false);
            await _fixture.UsersClient.AddUserAsync(user3).ConfigureAwait(false);

            // act
            var userSummaries = await _fixture.UsersClient.GetUserSummariesAsync($"{TestConfig.EmailPrefix}query_test_").ConfigureAwait(false);

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
            string email = GetEmail();
            
            var originalUser = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                FirstName = "Test",
                LastName = "User",
                PhoneNumber = "+123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" }, { "claim2", "A" } },
            };

            var expectedUser = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                FirstName = "Changed",
                LastName = "Name",
                PhoneNumber = "+987654321",
                Roles = { "auth_admin", "user_admin" },
                Claims = { { "claim2", "B" }, { "claim3", "3" } },
            };

            var initialUser = await _fixture.UsersClient.AddUserAsync(originalUser).ConfigureAwait(false);

            // act
            var actualUser = await _fixture.UsersClient.ModifyUserAsync(expectedUser, originalUser.Username).ConfigureAwait(false);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(expectedUser, options => options.Excluding(user => user.Id).Excluding(user => user.FullName).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.FirstName.Should().Be("Changed");
            actualUser.LastName.Should().Be("Name");
            actualUser.FullName.Should().Be("Changed Name");
            actualUser.PhoneNumber.Should().Be("+987654321");
            actualUser.Claims.Should().Contain(expectedUser.Claims);
            actualUser.Claims.Should().NotContain(originalUser.Claims);
            actualUser.Id.Should().Be(initialUser.Id);
        }

        [Fact]
        public async Task CanRemoveUser()
        {
            // arrange
            string email = GetEmail();
            
            var user = new User
            {
                Username = email,
                Email = email,
                Password = TestConfig.DefaultPassword
            };

            await _fixture.UsersClient.AddUserAsync(user).ConfigureAwait(false);

            // act
            await _fixture.UsersClient.RemoveUserAsync(user.Username).ConfigureAwait(false);

            // assert
            var userSummaries = await _fixture.UsersClient.GetUserSummariesAsync(TestConfig.EmailPrefix).ConfigureAwait(false);
            userSummaries.Should().NotBeNull();
            userSummaries.Should().NotContain(summary => summary.Username == user.Username);
        }

        [Fact]
        public async Task CanUseUser()
        {
            // arrange
            string email = GetEmail();
            
            var user = new User
            {
                Username = email,
                Email = email,
                Password = TestConfig.DefaultPassword
            };

            await _fixture.UsersClient.AddUserAsync(user).ConfigureAwait(false);

            // act
            var automation = new BrowserAutomation(user.Username, user.Password);
            var browser = new Browser(automation);
            var options = new OidcClientOptions
            {
                Authority = Authority,
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
            var user = new User();

            // act
            Func<Task> func = async () => await _fixture.UsersClient.AddUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>();
        }

        [Fact]
        public async Task CannotAddDuplicateUser()
        {
            // arrange
            string email = GetEmail();
            
            var user = new User
            {
                Username = email,
                Email = email,
                Password = TestConfig.DefaultPassword
            };

            await _fixture.UsersClient.AddUserAsync(user).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await _fixture.UsersClient.AddUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.Conflict);
        }

        [Fact]
        public void CannotRemoveDefaultAdminUser()
        {
            // arrange
            var username = TestConfig.DefaultAdminUserEmail;

            // act
            Func<Task> func = async () => await _fixture.UsersClient.RemoveUserAsync(username).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public void CannotRemoveAdminRoleFromDefaultAdminUser()
        {
            // arrange
            var user = new User
            {
                Username = TestConfig.DefaultAdminUserEmail,
                Roles = { }
            };

            // act
            Func<Task> func = async () => await _fixture.UsersClient.ModifyUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public void CannotAddUserWithNonExistingRole()
        {
            // arrange
            string email = GetEmail();

            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = { "admin", "lambo_owner" },
            };

            // act
            Func<Task> func = async () => await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CannotModifyUserRolesWithNonExistingRole()
        {
            // arrange
            string email = GetEmail();

            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = { "admin" },
            };

            await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model.Roles.Add("lambo_owner");

            Func<Task> func = async () => await _fixture.UsersClient.ModifyUserAsync(model).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CannotModifyUserClaimsWithInvalidClaimValues()
        {
            // arrange
            string email = GetEmail();

            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" } },
            };

            await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model.Claims = new Dictionary<string, object> { { string.Empty, null } };

            Func<Task> func = async () => await _fixture.UsersClient.ModifyUserAsync(model).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanRemoveUserClaims()
        {
            // arrange
            string email = GetEmail();

            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" }, { "claim2", "2" } },
            };

            var originalUser = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            var updateModel = new User
            {
                Username = originalUser.Username,
                Roles = null, // do *not* update roles
                Claims = { }, // *do* update claims
            };

            // act
            var actualUser = await _fixture.UsersClient.ModifyUserAsync(updateModel, updateModel.Username).ConfigureAwait(false);

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
            string email = GetEmail();

            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = { "admin" },
                Claims = { { "claim1", "1" }, { "claim2", "2" } },
            };

            var originalUser = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model = new User
            {
                Username = originalUser.Username,
                Roles = { }, // do *not* update roles
                Claims = null, // *do* update claims
            };

            // act
            var actualUser = await _fixture.UsersClient.ModifyUserAsync(model, model.Username).ConfigureAwait(false);

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
            string email = GetEmail();

            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789"
            };

            var originalUser = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await _fixture.UsersClient.AddRolesAsync(originalUser.Username, new[] {"admin"});

            var actualUser = await _fixture.UsersClient.GetUserAsync(originalUser.Username);

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
            string email = GetEmail();
            
            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = { "admin" }
            };

            var originalUser = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            Func<Task> func = async () => await _fixture.UsersClient.AddRolesAsync(originalUser.Username, new[] { "lambo_owner" }).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanRemoveUserFromRoles()
        {
            // arrange
            string email = GetEmail();
            
            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Roles = {"admin"}
            };

            var originalUser = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await _fixture.UsersClient.RemoveRolesAsync(originalUser.Username, new[] {"admin"});

            var actualUser = await _fixture.UsersClient.GetUserAsync(originalUser.Username).ConfigureAwait(false);

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
            // act
            Func<Task> func = async () =>
                await _fixture.UsersClient.RemoveRolesAsync(TestConfig.DefaultAdminUserEmail, new[] {"admin"}).ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanAddUserClaims()
        {
            // arrange
            string email = GetEmail();
            
            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultAdminUserEmail,
                Email = email,
                PhoneNumber = "+123456789"
            };

            var originalUser = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await _fixture.UsersClient.AddClaimsAsync(originalUser.Username,
                new Dictionary<string, object>
                {
                    { "claim1", new object[] {"1", "2", "3"} },
                    { "claim2", new object[] {"21", "22", "23"} }
                });

            var actualUser = await _fixture.UsersClient.GetUserAsync(originalUser.Username);

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
            string email = GetEmail();
            
            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789"
            };

            var user = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            model.Claims = new Dictionary<string, object> { { string.Empty, null } };

            Func<Task> func = async () =>
                await _fixture.UsersClient
                    .AddClaimsAsync(user.Username, new Dictionary<string, object> { {string.Empty, null} })
                    .ConfigureAwait(false);

            // assert
            func.Should().Throw<HttpException>().And.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task CanRemoveUserClaim()
        {
            // arrange
            string email = GetEmail();

            var model = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "+123456789",
                Claims = new Dictionary<string, object> { {"claim1", "1"}, {"claim2", "2"} }
            };

            var originalUser = await _fixture.UsersClient.AddUserAsync(model).ConfigureAwait(false);

            // act
            await _fixture.UsersClient.RemoveClaimsAsync(originalUser.Username, new Dictionary<string, object> { {"claim1", new List<object> {"1"} } });

            var actualUser = await _fixture.UsersClient.GetUserAsync(originalUser.Username);

            // assert
            actualUser.Should().NotBeNull();
            actualUser.Should().BeEquivalentTo(originalUser, options => options.Excluding(user => user.Id).Excluding(user => user.Password).Excluding(user => user.Claims));
            actualUser.Id.Should().Be(originalUser.Id);
            actualUser.Claims.Should().NotBeEmpty();
            actualUser.Claims.Should().NotContainKey("claim1");
            actualUser.Claims.Should().ContainKey("claim2");
        }

        public void Dispose()
        {
            _fixture.UsersClient.RemoveUsersAsync(TestConfig.EmailPrefix).GetAwaiter().GetResult();
        }

        private static string GetEmail() => $"{TestConfig.EmailPrefix}{Guid.NewGuid():N}@test.com";
    }
}
