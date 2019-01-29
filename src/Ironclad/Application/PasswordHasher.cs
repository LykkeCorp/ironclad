using Common.PasswordTools;
using Ironclad.Configuration;
using Lykke.Service.ClientAccount.Client;
using Microsoft.AspNetCore.Identity;

namespace Ironclad.Application
{
    public class PasswordHasher : IPasswordHasher<ApplicationUser>
    {
        private readonly IClientAccountClient clientAccountClient;

        public PasswordHasher(IClientAccountClient clientAccountClient)
        {
            this.clientAccountClient = clientAccountClient;
        }

        public string HashPassword(ApplicationUser user, string password)
        {
            user.PasswordHash = PasswordKeepingUtils.GetClientHashedPwd(password);
            return user.PasswordHash;
        }

        public PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword, string providedPassword)
        {
            return this.clientAccountClient.IsPasswordCorrectAsync(user.Id, providedPassword).GetAwaiter().GetResult()
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }
    }
}
