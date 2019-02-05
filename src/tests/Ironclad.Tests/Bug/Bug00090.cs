// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

using System;
using System.Threading.Tasks;
using FluentAssertions;
using Ironclad.Client;
using Ironclad.Tests.Sdk;
using Xunit;

namespace Ironclad.Tests.Bug
{
    public class Bug00090 : AuthenticationTest, IDisposable
    {
        private readonly AuthenticationFixture _fixture;
        private readonly string _email;
        
        public Bug00090(AuthenticationFixture fixture)
            : base(fixture)
        {
            _fixture = fixture;
            _email = $"{TestConfig.EmailPrefix}{Guid.NewGuid():N}@test.com";
        }

        [Fact]
        public async Task ShouldNotThrowInternalServerError()
        {
            // arrange
            var user = new User
            {
                Username = _email,
                Password = TestConfig.DefaultPassword,
                Email = _email,
                PhoneNumber = "0123456789",
                Roles = { "auth_admin", "user_admin" }
            };

            // act
            Func<Task> func = async () => await _fixture.UsersClient.AddUserAsync(user).ConfigureAwait(false);

            // assert
            func.Should().NotThrow<HttpException>();
        }

        public void Dispose()
        {
            _fixture.UsersClient.RemoveUserAsync(_email).GetAwaiter().GetResult();
        }
    }
}
