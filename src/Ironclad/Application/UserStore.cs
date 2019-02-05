namespace Ironclad.Application
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading;
    using System.Threading.Tasks;
    using ExternalIdentityProvider;
    using Lykke.Service.ClientAccount.Client;
    using Lykke.Service.ClientAccount.Client.Models;
    using Lykke.Service.PersonalData.Contract;
    using Lykke.Service.PersonalData.Contract.Models;
    using Lykke.Service.Registration;
    using Lykke.Service.Registration.Contract.Client.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;
    using ClientAccountInformationModel = Lykke.Service.ClientAccount.Client.Models.ClientAccountInformationModel;

    public class UserStore : IUserPasswordStore<ApplicationUser>,
                             IUserRoleStore<ApplicationUser>,
                             IUserClaimStore<ApplicationUser>,
                             IUserLoginStore<ApplicationUser>
    {
        private readonly IClientAccountClient clientAccountClient;
        private readonly IPersonalDataService personalDataService;
        private readonly IRegistrationServiceClient registrationServiceClient;
        private readonly Decorator<IUserStore<ApplicationUser>> userStoreOrig;
        private readonly ILogger<UserStore> logger;

        public UserStore(
            IClientAccountClient clientAccountClient,
            IPersonalDataService personalDataService,
            IRegistrationServiceClient registrationServiceClient,
            Decorator<IUserStore<ApplicationUser>> userStoreOrig,
            ILogger<UserStore> logger)
        {
            this.clientAccountClient = clientAccountClient;
            this.personalDataService = personalDataService;
            this.registrationServiceClient = registrationServiceClient;
            this.userStoreOrig = userStoreOrig;
            this.logger = logger;
        }

        public void Dispose()
        {
        }

        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user?.Id);
        }

        public Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user?.UserName);
        }

        public Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken)
        {
            // TODO: update first name/lastname
            return Task.CompletedTask;
        }

        public Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(string.Empty);
        }

        public Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            AccountsRegistrationResponseModel result = await this.registrationServiceClient.RegistrationApi.RegisterAsync(
                new AccountRegistrationModel
                {
                    Email = user.UserName,
                    ContactPhone = user.PhoneNumber,
                    Password = user.PasswordHash,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    FullName = user.FullName,
                    CreatedAt = DateTime.UtcNow
                }, cancellationToken);

            if (result != null)
            {
                user.Id = result.Account.Id;

                await this.userStoreOrig.Instance.CreateAsync(new ApplicationUser
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    NormalizedUserName = user.UserName.ToUpper(),
                    NormalizedEmail = user.Email.ToUpper(),
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    FullName = user.FullName
                }, cancellationToken);
            }

            return result != null ? IdentityResult.Success : IdentityResult.Failed();
        }

        public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            // TODO: client information update
            return await this.UpdateOriginalStore(user, cancellationToken);
        }

        private async Task<IdentityResult> UpdateOriginalStore(ApplicationUser user, CancellationToken cancellationToken)
        {
            var existingUser = await this.userStoreOrig.Instance.FindByIdAsync(user.Id, cancellationToken);
            return existingUser != null
                ? await this.userStoreOrig.Instance.UpdateAsync(existingUser, cancellationToken)
                : await this.userStoreOrig.Instance.CreateAsync(user, cancellationToken);
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            try
            {
                var tasks = new List<Task>();
                string clientId = null;

                var origUser = await userStoreOrig.Instance.FindByNameAsync(user.NormalizedUserName, cancellationToken);

                if (origUser == null)
                {
                    var client = await this.clientAccountClient.GetClientByEmailAndPartnerIdAsync(user.Email, null);

                    if (client != null)
                    {
                        clientId = client.Id;
                    }
                }
                else
                {
                    clientId = origUser.Id;
                }

                if (!string.IsNullOrEmpty(clientId))
                {
                    tasks.Add(clientAccountClient.DeleteAccountAsync(clientId));
                    tasks.Add(personalDataService.ArchiveAsync(clientId, "ironclad"));
                    await Task.WhenAll(tasks);
                    
                    if (origUser != null)
                    {
                        var result = await this.userStoreOrig.Instance.DeleteAsync(origUser, cancellationToken);
                        return result;
                    }
                    
                    return IdentityResult.Success;
                }

                return IdentityResult.Failed(new IdentityError {Code = "UserNotFound", Description = "User not found"});
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "Exception",
                    Description = ex.Message
                });
            }
        }

        public async Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            try
            {
                ClientModel client = await this.clientAccountClient.GetByIdAsync(userId);

                if (client != null)
                {
                    IPersonalData pd = await this.personalDataService.GetAsync(userId);
                    return new ApplicationUser(client, pd);
                }
            }
            catch (Exception)
            {
                return null;
            }

            return null;
        }

        public async Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            // find user in postgres database first, this will work for new users created using ironclad or tests
            // this is a workaround for client account method GetClientByEmailAndPartnerIdAsync which caches not existing client requests
            var user = await this.userStoreOrig.Instance.FindByNameAsync(normalizedUserName, cancellationToken);

            ClientModel client = null;

            try
            {
                if (user != null)
                {
                    client = await this.clientAccountClient.GetByIdAsync(user.Id);
                }
                else
                {
                    ClientAccountInformationModel clientInfo = await this.clientAccountClient
                        .GetClientByEmailAndPartnerIdAsync(normalizedUserName.ToLower(), null).ConfigureAwait(false);

                    if (clientInfo != null)
                    {
                        client = await this.clientAccountClient.GetByIdAsync(clientInfo.Id);
                    }
                }
            }
            catch (Exception ex)
            {
                this.logger.LogWarning($"User {normalizedUserName.ToLower()} not found");
            }

            if (client != null)
            {
                IPersonalData pd = await this.personalDataService.GetAsync(client.Id);
                return new ApplicationUser(client, pd);
            }

            return null;
        }

        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            // TODO: currently there is no method to get client password hash
            return Task.FromResult(string.Empty);
        }

        public Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }

        public async Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            await ((IUserRoleStore<ApplicationUser>)this.userStoreOrig.Instance).AddToRoleAsync(user, roleName,
                cancellationToken);
        }

        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            return ((IUserRoleStore<ApplicationUser>)this.userStoreOrig.Instance).RemoveFromRoleAsync(user, roleName,
                cancellationToken);
        }

        public Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return ((IUserRoleStore<ApplicationUser>)this.userStoreOrig.Instance).GetRolesAsync(user, cancellationToken);
        }

        public Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            return ((IUserRoleStore<ApplicationUser>)this.userStoreOrig.Instance).IsInRoleAsync(user, roleName, cancellationToken);
        }

        public Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            return ((IUserRoleStore<ApplicationUser>)this.userStoreOrig.Instance).GetUsersInRoleAsync(roleName, cancellationToken);
        }

        public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return ((IUserClaimStore<ApplicationUser>)this.userStoreOrig.Instance).GetClaimsAsync(user, cancellationToken);
        }

        public Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            return ((IUserClaimStore<ApplicationUser>)this.userStoreOrig.Instance).AddClaimsAsync(user, claims, cancellationToken);
        }

        public Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            return ((IUserClaimStore<ApplicationUser>)this.userStoreOrig.Instance).ReplaceClaimAsync(user, claim, newClaim, cancellationToken);
        }

        public Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            return ((IUserClaimStore<ApplicationUser>)this.userStoreOrig.Instance).RemoveClaimsAsync(user, claims, cancellationToken);
        }

        public Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            return ((IUserClaimStore<ApplicationUser>)this.userStoreOrig.Instance).GetUsersForClaimAsync(claim, cancellationToken);
        }

        public Task AddLoginAsync(ApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            var result = new List<UserLoginInfo>();

            return Task.FromResult((IList<UserLoginInfo>)result);
        }

        public Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var result = new ApplicationUser();

            return Task.FromResult(result);
        }
    }
}
