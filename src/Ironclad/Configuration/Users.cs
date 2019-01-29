// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Configuration
{
    using Ironclad.Application;

    public static partial class Config
    {
        public const string DefaultAdminUserEmail = "ironcladadmin@test.com";

        public static ApplicationUser GetDefaultAdminUser() => new ApplicationUser
        {
            UserName = DefaultAdminUserEmail, 
            Email = DefaultAdminUserEmail,
            NormalizedEmail = DefaultAdminUserEmail.ToUpper(),
            NormalizedUserName = DefaultAdminUserEmail.ToUpper()
        };
    }
}
