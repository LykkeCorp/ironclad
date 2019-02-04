// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Data.Maintenance
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using IdentityServer4.Postgresql.Entities;
    using IdentityServer4.Postgresql.Mappers;
    using Ironclad.Application;
    using Ironclad.Configuration;
    using Marten;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.Extensions.Logging;

    public class SynchronizationManager
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IDocumentStore documentStore;
        private readonly ILogger logger;

        public SynchronizationManager(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IDocumentStore documentStore,
            ILogger<SynchronizationManager> logger)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.documentStore = documentStore;
            this.logger = logger;
        }

        public async Task SynchonizeAdminUserAsync()
        {
            var adminUser = await this.userManager.FindByNameAsync(Config.DefaultAdminUserEmail);

            if (adminUser != null)
            {
                return;
            }

            this.logger.LogInformation("Configuring system for first use...");

            await this.roleManager.CreateAsync(new IdentityRole("admin"));
            await this.roleManager.CreateAsync(new IdentityRole("auth_admin"));
            await this.roleManager.CreateAsync(new IdentityRole("user_admin"));

            adminUser = Config.GetDefaultAdminUser();

            await this.userManager.CreateAsync(adminUser, "password");
            await this.userManager.AddToRoleAsync(adminUser, "admin");
        }

        public async Task SynchronizeConfigurationAsync(string authApiSecret)
        {
            using (var session = this.documentStore.LightweightSession())
            {
                this.logger.LogInformation("Synchronizing default clients...");
                var clientSecretsComparer = new KeyEqualityComparer<ClientSecret>(secret => secret.Value);
                var clients = Config.GetDefaultClients().Select(x => x.ToEntity());
                foreach (var client in clients)
                {
                    var exisingClients = await session.Query<Client>().Where(document => document.ClientId == client.ClientId).ToListAsync();
                    if (exisingClients.Any())
                    {
                        session.DeleteWhere<Client>(document => document.ClientId == client.ClientId);
                        client.ClientSecrets = exisingClients[0].ClientSecrets.Union(client.ClientSecrets, clientSecretsComparer).ToList();
                    }

                    session.Store(client);
                }

                this.logger.LogInformation("Synchronizing default API resources...");
                var apiResourceSecretsComparer = new KeyEqualityComparer<ApiSecret>(secret => secret.Value);
                var apiResources = Config.GetDefaultApiResources(authApiSecret).Select(x => x.ToEntity());
                foreach (var apiResource in apiResources)
                {
                    var exisingApiResources = await session.Query<ApiResource>().Where(document => document.Name == apiResource.Name).ToListAsync();
                    if (exisingApiResources.Any())
                    {
                        session.DeleteWhere<ApiResource>(document => document.Name == apiResource.Name);
                        apiResource.Secrets = exisingApiResources[0].Secrets.Union(apiResource.Secrets, apiResourceSecretsComparer).ToList();
                    }

                    session.Store(apiResource);
                }

                this.logger.LogInformation("Synchronizing default identity resources...");
                var identityResources = Config.GetDefaultIdentityResources().Select(x => x.ToEntity());
                foreach (var identityResource in identityResources)
                {
                    var exisingApiResources = await session.Query<IdentityResource>().Where(document => document.Name == identityResource.Name).ToListAsync();
                    if (exisingApiResources.Any())
                    {
                        session.DeleteWhere<IdentityResource>(document => document.Name == identityResource.Name);
                    }

                    session.Store(identityResource);
                }

                session.SaveChanges();
            }
        }

        private class KeyEqualityComparer<T> : IEqualityComparer<T>
        {
            private readonly Func<T, object> keyExtractor;

            public KeyEqualityComparer(Func<T, object> keyExtractor) => this.keyExtractor = keyExtractor;

            public bool Equals(T x, T y) => this.keyExtractor(x).Equals(this.keyExtractor(y));

            public int GetHashCode(T obj) => this.keyExtractor(obj).GetHashCode();
        }
    }
}
