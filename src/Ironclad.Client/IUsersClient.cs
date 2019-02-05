// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Client
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Exposes the public members of the users client.
    /// </summary>
    public interface IUsersClient
    {
        /// <summary>
        /// Get the user summaries (or a subset thereof).
        /// </summary>
        /// <param name="startsWith">The start of the username.</param>
        /// <param name="start">The zero-based start ordinal of the user set to return.</param>
        /// <param name="size">The total size of the user set.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The user summaries.</returns>
        Task<ResourceSet<UserSummary>> GetUserSummariesAsync(string startsWith, int start = 0, int size = 20, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The user.</returns>
        Task<User> GetUserAsync(string username, CancellationToken cancellationToken = default);

        /// <summary>
        /// Adds the specified user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The new user.</returns>
        Task<User> AddUserAsync(User user, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        Task RemoveUserAsync(string username, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes users by email pattern.
        /// </summary>
        /// <param name="emailPattern">The email pattern.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        Task RemoveUsersAsync(string emailPattern, CancellationToken cancellationToken = default);

        /// <summary>
        /// Modifies the specified user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="currentUsername">The current username (if different from the specified user username).</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The modified user.</returns>
        Task<User> ModifyUserAsync(User user, string currentUsername = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets claims for the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The list of claims.</returns>
        Task<IDictionary<string, object>> GetClaimsAsync(string username, CancellationToken cancellationToken = default);

        /// <summary>
        /// Adds claims to the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="claims">The list of claims to be added.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        Task AddClaimsAsync(string username, IEnumerable<KeyValuePair<string, object>> claims, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes claims from the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="claims">The list of claims to be removed.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        Task RemoveClaimsAsync(string username, IEnumerable<KeyValuePair<string, object>> claims, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets roles for the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The list of roles.</returns>
        Task<IEnumerable<string>> GetRolesAsync(string username, CancellationToken cancellationToken = default);

        /// <summary>
        /// Add roles to the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="roles">The list of roles to be added.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        Task AddRolesAsync(string username, IEnumerable<string> roles, CancellationToken cancellationToken = default);

        /// <summary>
        /// Removes roles from the specified user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="roles">The list of roles to be removed.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>A task object representing the asynchronous operation.</returns>
        Task RemoveRolesAsync(string username, IEnumerable<string> roles, CancellationToken cancellationToken = default);
    }
}
