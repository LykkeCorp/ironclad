// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Tests.Bug
{
    using System;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Client;
    using Sdk;
    using Xunit;

    public class Bug00090 : AuthenticationTest, IDisposable
    {
        private string email;
        public Bug00090(AuthenticationFixture fixture)
            : base(fixture)
        {
            this.email = $"{TestConfig.EmailPrefix}{Guid.NewGuid():N}@test.com";
        }

        [Fact]
        public async Task ShouldNotThrowInternalServerError()
        {
            // arrange
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);

            var user = new User
            {
                Username = email,
                Password = TestConfig.DefaultPassword,
                Email = email,
                PhoneNumber = "0123456789",
                Roles = { "auth_admin", "user_admin" },
            };

            // act
            Func<Task> func = async () => await httpClient.AddUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().NotThrow<HttpException>();
        }

        public void Dispose()
        {
            var httpClient = new UsersHttpClient(this.ApiUri, this.Handler);
            httpClient.RemoveUserAsync(this.email).GetAwaiter().GetResult();
        }
    }
}
