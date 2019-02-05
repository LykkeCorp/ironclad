// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

#pragma warning disable CA2227

namespace Ironclad.Client
{
    using System.Collections.Generic;

    /// <summary>
    /// Represents a user.
    /// </summary>
    public class User
    {
        /// <summary>
        /// Gets or sets the subject identifier for this user.
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// Gets or sets the username for this user.
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Gets or sets the password for this user.
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the email address for this user.
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// Gets or sets a flag indicating whether to send a confirmation email to the new user.
        /// </summary>
        public bool? SendConfirmationEmail { get; set; }

        /// <summary>
        /// Gets or sets a telephone number for the user.
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        /// Gets or sets the external login provider for the user.
        /// </summary>
        public string ExternalLoginProvider { get; set; }

        /// <summary>
        /// Gets or sets the external login providers for the user.
        /// </summary>
        public ICollection<string> ExternalLoginProviders { get; set; }

        /// <summary>
        /// Gets or sets the registration link for this user.
        /// </summary>
        public string RegistrationLink { get; set; }

        /// <summary>
        /// Gets or sets the roles.
        /// </summary>
        /// <value>The roles.</value>
        public ICollection<string> Roles { get; set; }
#if CLIENT
            = new HashSet<string>();
#endif

        /// <summary>
        /// Gets or sets the user's claims.
        /// </summary>
        /// <value>The user's claims.</value>
        public IDictionary<string, object> Claims { get; set; }
#if CLIENT
            = new Dictionary<string, object>();
#endif

        /// <summary>
        /// Gets or sets the user's first name.
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        /// Gets or sets the user's last name.
        /// </summary>
        public string LastName { get; set; }

        /// <summary>
        /// Gets or sets the user's last name.
        /// </summary>
        public string FullName { get; set; }
    }
}
