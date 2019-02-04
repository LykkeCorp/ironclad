// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

// TODO (Cameron): Refactor and remove when JSON configuration supports snake case.
#pragma warning disable IDE1006, SA1300, SA1202
#pragma warning disable CA1812, CA1308, CA1034, CA1056, CA1707, CA1724

namespace Ironclad
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using Microsoft.Azure.KeyVault;
    using Microsoft.Azure.Services.AppAuthentication;

    // TODO (Cameron): This class is a huge mess - for many reasons. Something needs to be done...
    public sealed class Settings
    {
        public ServerSettings Server { get; set; }

        public ApiSettings Api { get; set; }

        public WebsiteSettings Website { get; set; }

        public IdpSettings Idp { get; set; }

        public MailSettings Mail { get; set; }

        public AzureSettings Azure { get; set; }
        
        public ClientsSettings Clients { get; set; }

        public void Validate()
        {
            var sections = new Dictionary<string, IEnumerable<string>>();

            if (this.Server == null)
            {
                sections.Add(nameof(this.Server), new[] { "Missing section." });
            }
            else if (this.Server.GetValidationErrors().Any() == true)
            {
                sections.Add(nameof(this.Server), this.Server.GetValidationErrors());
            }

            if (this.Server?.SigningCertificate?.GetValidationErrors().Any() == true)
            {
                sections.Add($"{nameof(this.Server)}:{nameof(this.Server.signing_certificate)}", this.Server.SigningCertificate.GetValidationErrors());
            }

            if (this.Server?.DataProtection?.GetValidationErrors().Any() == true)
            {
                sections.Add($"{nameof(this.Server)}:{nameof(this.Server.data_protection)}", this.Server.DataProtection.GetValidationErrors());
            }

            if (this.Api == null)
            {
                sections.Add(nameof(this.Api), new[] { "Missing section." });
            }
            else if (this.Api?.GetValidationErrors().Any() == true)
            {
                sections.Add(nameof(this.Api), this.Api.GetValidationErrors());
            }

            if (this.Idp?.Google?.GetValidationErrors().Any() == true)
            {
                sections.Add(nameof(this.Idp.Google), this.Idp.Google.GetValidationErrors());
            }

            if (this.Mail?.GetValidationErrors().Any() == true)
            {
                sections.Add(nameof(this.Mail), this.Mail.GetValidationErrors());
            }

            if (this.Azure?.KeyVault?.GetValidationErrors().Any() == true)
            {
                sections.Add($"{nameof(this.Azure)}:{nameof(this.Azure.key_vault)}", this.Azure.KeyVault.GetValidationErrors());
            }

            if (sections.Any())
            {
                var builder = new StringBuilder();
                foreach (var section in sections)
                {
                    var errors = section.Value.Select(value => string.Format(CultureInfo.InvariantCulture, value, section.Key.ToLowerInvariant()));
                    builder.Append($"\r\nErrors in '{section.Key.ToLowerInvariant()}' section:\r\n - {string.Join("\r\n - ", errors)}");
                }

                // TODO (Cameron): Change link to point to somewhere sensible (when it exists).
                throw new InvalidOperationException(
                    $@"Validation of configuration settings failed.{builder.ToString()}
Please see https://gist.github.com/cameronfletcher/58673a468c8ebbbf91b81e706063ba56 for more information.");
            }
        }

        public sealed class ServerSettings
        {
            public string Database { get; set; }

            public string IssuerUri => this.issuer_uri;

            public bool RespectXForwardedForHeaders => this.respect_x_forwarded_for_headers == false ? false : true;

            public SigningCertificateSettings SigningCertificate => this.signing_certificate;

            public DataProtectionSettings DataProtection => this.data_protection;

            private string issuer_uri { get; set; }

            private bool? respect_x_forwarded_for_headers { get; set; }

            internal SigningCertificateSettings signing_certificate { get; set; }

            internal DataProtectionSettings data_protection { get; set; }

            public bool IsValid() => !this.GetValidationErrors().Any();

            public IEnumerable<string> GetValidationErrors()
            {
                if (string.IsNullOrEmpty(this.Database))
                {
                    yield return $"'{{0}}:{nameof(this.Database).ToLowerInvariant()}' is null or empty.";
                }
            }

            public sealed class SigningCertificateSettings
            {
                public string Filepath { get; set; }

                public string Password { get; set; }

                public string Thumbprint { get; set; }

                public string CertificateId => this.certificate_id;

                private string certificate_id { get; set; }

                public bool IsValid() => !this.GetValidationErrors().Any();

                public IEnumerable<string> GetValidationErrors()
                {
                    var keys = string.Join(
                        ", ",
                        new[] { nameof(this.Thumbprint), nameof(this.Filepath), nameof(this.certificate_id) }.Select(name => $"'{{0}}:{name.ToLowerInvariant()}'"));

                    if (string.IsNullOrEmpty(this.Filepath) && string.IsNullOrEmpty(this.Thumbprint) && string.IsNullOrEmpty(this.CertificateId))
                    {
                        yield return $"All of the following configuration settings are either null or empty (which is invalid): {keys}.";
                    }

                    if (new[] { string.IsNullOrEmpty(this.Filepath), string.IsNullOrEmpty(this.Thumbprint), string.IsNullOrEmpty(this.CertificateId) }
                        .Where(condition => !condition)
                        .Count() > 1)
                    {
                        yield return $"More than one of the following configuration settings have values (which is invalid): {keys}.";
                    }
                }
            }

            public sealed class DataProtectionSettings
            {
                public string KeyfileUri => this.keyfile_uri;

                public string KeyId => this.key_id;

                public string keyfile_uri { get; set; }

                public string key_id { get; set; }

                public bool IsValid() => !this.GetValidationErrors().Any();

                public IEnumerable<string> GetValidationErrors()
                {
                    if (string.IsNullOrEmpty(this.KeyfileUri) || string.IsNullOrEmpty(this.KeyId))
                    {
                        yield return
                            $"One or more of '{{0}}:{nameof(this.keyfile_uri).ToLowerInvariant()}' and '{{0}}:{nameof(this.key_id).ToLowerInvariant()}' are null or empty.";
                    }
                }
            }
        }

        public sealed class ApiSettings
        {
            public string Authority { get; set; }

            public string Audience { get; set; }

            public string ClientId => this.client_id;

            public string OmitUriForRequestsFrom => this.omit_uri_for_requests_from;

            public string Secret { get; set; }

            public string Uri { get; set; }

            private string client_id { get; set; }

            private string omit_uri_for_requests_from { get; set; }

            public bool IsValid() => !this.GetValidationErrors().Any();

            public IEnumerable<string> GetValidationErrors()
            {
                if (string.IsNullOrEmpty(this.Authority))
                {
                    yield return $"'{{0}}:{nameof(this.Authority).ToLowerInvariant()}' is null or empty.";
                }

                if (string.IsNullOrEmpty(this.Audience))
                {
                    yield return $"'{{0}}:{nameof(this.Audience).ToLowerInvariant()}' is null or empty.";
                }

                if (string.IsNullOrEmpty(this.ClientId))
                {
                    yield return $"'{{0}}:{nameof(this.client_id).ToLowerInvariant()}' is null or empty.";
                }

                if (string.IsNullOrEmpty(this.Secret))
                {
                    yield return $"'{{0}}:{nameof(this.Secret).ToLowerInvariant()}' is null or empty.";
                }
            }
        }

        public sealed class WebsiteSettings
        {
            public string PathBase { get; set; }

            public bool IsValid() => !this.GetValidationErrors().Any();

            public IEnumerable<string> GetValidationErrors()
            {
                // Note (Pawel) if you add validation here, please make sure to make this config section mandatory
                // (for now it is optional)
                return Array.Empty<string>();
            }
        }

        public class IdpSettings
        {
            public IEnumerable<string> RestrictedDomains => this.restricted_domains ?? new HashSet<string>();

            public GoogleSettings Google { get; set; }

            private HashSet<string> restricted_domains { get; set; }

            public class GoogleSettings
            {
                public string ClientId => this.client_id;

                public string Secret { get; set; }

                private string client_id { get; set; }

                public bool IsValid() => !this.GetValidationErrors().Any();

                public IEnumerable<string> GetValidationErrors()
                {
                    if (string.IsNullOrEmpty(this.ClientId))
                    {
                        yield return $"'{{0}}:{nameof(this.client_id).ToLowerInvariant()}' is null or empty.";
                    }

                    if (string.IsNullOrEmpty(this.Secret))
                    {
                        yield return $"'{{0}}:{nameof(this.Secret).ToLowerInvariant()}' is null or empty.";
                    }
                }
            }
        }

        public sealed class MailSettings
        {
            public string Sender { get; set; }

            public string Host { get; set; }

            public int Port { get; set; }

            public bool EnableSsl => this.enable_ssl;

            public string Username { get; set; }

            public string Password { get; set; }

            private bool enable_ssl { get; set; }

            public bool IsValid() => !this.GetValidationErrors().Any();

            public IEnumerable<string> GetValidationErrors()
            {
                if (string.IsNullOrEmpty(this.Sender))
                {
                    yield return $"'{{0}}:{nameof(this.Sender).ToLowerInvariant()}' is null or empty.";
                }

                if (string.IsNullOrEmpty(this.Host))
                {
                    yield return $"'{{0}}:{nameof(this.Host).ToLowerInvariant()}' is null or empty.";
                }

                if (!string.IsNullOrEmpty(this.Username) && string.IsNullOrEmpty(this.Password))
                {
                    yield return $"'{{0}}:{nameof(this.Password).ToLowerInvariant()}' is null or empty but '{{0}}{nameof(this.Username)}' is not.";
                }
            }
        }

        public sealed class AzureSettings
        {
            public KeyVaultSettings KeyVault => this.key_vault;

            internal KeyVaultSettings key_vault { get; set; }

            public sealed class KeyVaultSettings : IDisposable
            {
                private KeyVaultClient client;

                public string Name { get; set; }

                public string ConnectionString { get; set; }

                public string Endpoint => $"https://{this.Name}.vault.azure.net";

                public KeyVaultClient Client
                {
                    get
                    {
                        if (this.client != null)
                        {
                            return this.client;
                        }

                        if (!this.IsValid())
                        {
                            return null;
                        }

                        var tokenProvider = new AzureServiceTokenProvider(this.ConnectionString);
                        return this.client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
                    }
                }

                public bool IsValid() => !this.GetValidationErrors().Any();

                public IEnumerable<string> GetValidationErrors()
                {
                    if (string.IsNullOrEmpty(this.Name))
                    {
                        yield return $"'{{0}}:{nameof(this.Name).ToLowerInvariant()}' is null or empty.";
                    }
                }

                public void Dispose() => this.client?.Dispose();
            }
        }

        public sealed class ClientsSettings
        {
            public string ClientAccountServiceUrl { get; set; }

            public string RegistrationServiceUrl { get; set; }

            public string PersonalDataServiceUrl { get; set; }

            public string PersonalDataServiceKey { get; set; }
        }
    }
}
