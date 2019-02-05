// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Client
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Newtonsoft.Json;

    /// <summary>
    /// An HTTP client for managing users of the authorization server.
    /// </summary>
    public sealed class UsersHttpClient : HttpClientBase, IUsersClient
    {
        private const string ApiPath = "/users";
        private const string ApiClaimsPath = "/users/{0}/claims";
        private const string ApiRolesPath = "/users/{0}/roles";

        /// <summary>
        /// Initializes a new instance of the <see cref="UsersHttpClient"/> class.
        /// </summary>
        /// <param name="authority">The authority.</param>
        /// <param name="innerHandler">The inner handler.</param>
        public UsersHttpClient(string authority, HttpMessageHandler innerHandler = null)
            : base(authority, innerHandler)
        {
        }

        /// <inheritdoc />
        public Task<ResourceSet<UserSummary>> GetUserSummariesAsync(
            string startsWith,
            int start = 0,
            int size = 20,
            CancellationToken cancellationToken = default) =>
            this.GetAsync<ResourceSet<UserSummary>>(
                this.RelativeUrl($"{ApiPath}?username={WebUtility.UrlEncode(startsWith)}&skip={NotNegative(start, nameof(start))}&take={NotNegative(size, nameof(size))}"),
                cancellationToken);

        /// <inheritdoc />
        public Task<User> GetUserAsync(string username, CancellationToken cancellationToken = default) =>
            this.GetAsync<User>(this.RelativeUrl($"{ApiPath}/{WebUtility.UrlEncode(NotNull(username, nameof(username)))}"), cancellationToken);

        /// <inheritdoc />
        public async Task<User> AddUserAsync(User user, CancellationToken cancellationToken = default)
        {
            var registrationLink = default(string);

            try
            {
                using (var content = new StringContent(JsonConvert.SerializeObject(user, JsonSerializerSettings), Encoding.UTF8, "application/json"))
                using (var request = new HttpRequestMessage(HttpMethod.Post, this.RelativeUrl(ApiPath)) { Content = content })
                using (var response = await this.Client.SendAsync(request, cancellationToken).EnsureSuccess().ConfigureAwait(false))
                {
                    if (response.Content != null)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        registrationLink = JsonConvert.DeserializeObject<UserResponse>(responseContent, JsonSerializerSettings)?.RegistrationLink;

                        response.Content.Dispose();
                    }
                }
            }
            catch (HttpRequestException ex)
            {
                throw new HttpException(HttpMethod.Post, new Uri(this.RelativeUrl(ApiPath)), ex);
            }

            user = await this.GetUserAsync(user.Username, cancellationToken).ConfigureAwait(false);
            user.RegistrationLink = registrationLink;

            return user;
        }

        /// <inheritdoc />
        public Task RemoveUserAsync(string username, CancellationToken cancellationToken = default) =>
            this.DeleteAsync(this.RelativeUrl($"{ApiPath}/{WebUtility.UrlEncode(NotNull(username, nameof(username)))}"), cancellationToken);

        public Task RemoveUsersAsync(string emailPattern, CancellationToken cancellationToken = default) =>
            this.DeleteAsync(this.RelativeUrl($"{ApiPath}/byEmailPattern/{WebUtility.UrlEncode(NotNull(emailPattern, nameof(emailPattern)))}"), cancellationToken);

        /// <inheritdoc />
        public async Task<User> ModifyUserAsync(User user, string currentUsername = null, CancellationToken cancellationToken = default)
        {
            var url = this.RelativeUrl($"{ApiPath}/{WebUtility.UrlEncode(currentUsername ?? NotNull(user?.Username, "user.Username"))}");
            await this.SendAsync(HttpMethod.Put, url, user, cancellationToken).ConfigureAwait(false);
            return await this.GetUserAsync(user.Username, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public Task<IDictionary<string, object>> GetClaimsAsync(string username, CancellationToken cancellationToken = default) =>
            this.GetAsync<IDictionary<string, object>>(
                this.RelativeUrl(string.Format(CultureInfo.InvariantCulture, ApiClaimsPath, WebUtility.UrlEncode(NotNull(username, nameof(username))))),
                cancellationToken);

        /// <inheritdoc />
        public Task AddClaimsAsync(string username, IEnumerable<KeyValuePair<string, object>> claims, CancellationToken cancellationToken = default) =>
            this.SendAsync(
                HttpMethod.Post,
                this.RelativeUrl(string.Format(CultureInfo.InvariantCulture, ApiClaimsPath, WebUtility.UrlEncode(NotNull(username, nameof(username))))),
                Convert(claims),
                cancellationToken);

        /// <inheritdoc />
        public Task RemoveClaimsAsync(string username, IEnumerable<KeyValuePair<string, object>> claims, CancellationToken cancellationToken = default) =>
            this.SendAsync(
                HttpMethod.Delete,
                this.RelativeUrl(string.Format(CultureInfo.InvariantCulture, ApiClaimsPath, WebUtility.UrlEncode(NotNull(username, nameof(username))))),
                Convert(claims),
                cancellationToken);

        /// <inheritdoc />
        public Task<IEnumerable<string>> GetRolesAsync(string username, CancellationToken cancellationToken = default) =>
            this.GetAsync<IEnumerable<string>>(
                this.RelativeUrl(string.Format(CultureInfo.InvariantCulture, ApiRolesPath, WebUtility.UrlEncode(NotNull(username, nameof(username))))), cancellationToken);

        /// <inheritdoc />
        public Task AddRolesAsync(string username, IEnumerable<string> roles, CancellationToken cancellationToken = default) =>
            this.SendAsync(
                HttpMethod.Post,
                this.RelativeUrl(string.Format(CultureInfo.InvariantCulture, ApiRolesPath, WebUtility.UrlEncode(NotNull(username, nameof(username))))),
                roles,
                cancellationToken);

        /// <inheritdoc />
        public Task RemoveRolesAsync(string username, IEnumerable<string> roles, CancellationToken cancellationToken = default) =>
            this.SendAsync(
                HttpMethod.Delete,
                this.RelativeUrl(string.Format(CultureInfo.InvariantCulture, ApiRolesPath, WebUtility.UrlEncode(NotNull(username, nameof(username))))),
                roles,
                cancellationToken);

        private static IDictionary<string, object> Convert(IEnumerable<KeyValuePair<string, object>> claims)
        {
            var dictionary = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            foreach (var claim in claims)
            {
                if (dictionary.TryGetValue(claim.Key, out var value))
                {
                    if (value is List<object> list)
                    {
                        list.Add(claim.Value);
                    }
                    else
                    {
                        dictionary[claim.Key] = new List<object> { value, claim.Value };
                    }
                }
                else
                {
                    dictionary.Add(claim.Key, claim.Value);
                }
            }

            return dictionary;
        }

        #pragma warning disable CA1812
        internal class UserResponse
        {
            public string RegistrationLink { get; set; }
        }
    }
}
