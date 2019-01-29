// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Application
{
    using Microsoft.AspNetCore.Identity;
    
    using Lykke.Service.ClientAccount.Client.Models;
    using Lykke.Service.PersonalData.Contract.Models;

    public sealed class ApplicationUser : IdentityUser
    {
        [ProtectedPersonalData]
        public string FirstName { get; set; }

        [ProtectedPersonalData]
        public string LastName { get; set; }

        [ProtectedPersonalData]
        public string FullName { get; set; }

        public ApplicationUser()
        {
        }

        public ApplicationUser(string username)
            : this()
        {
            this.UserName = username;
            this.Email = username;
            this.NormalizedUserName = username.ToUpper();
            this.NormalizedEmail = username.ToUpper();
        }

        public ApplicationUser(ClientModel client, IPersonalData personalData)
            : this()
        {
            this.Id = client.Id;
            this.Email = personalData?.Email;
            this.NormalizedEmail = personalData?.Email.ToUpper();
            this.EmailConfirmed = client.IsEmailVerified;
            this.UserName = personalData?.Email;
            this.NormalizedUserName = personalData?.Email.ToUpper();
            this.FirstName = personalData?.FirstName;
            this.LastName = personalData?.LastName;
            this.FullName = personalData?.FullName;
            this.PhoneNumber = personalData?.ContactPhone;
            this.PhoneNumberConfirmed = client.IsPhoneVerified;
        }
    }
}
