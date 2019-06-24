// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Controllers
{
    using System.Reflection;
    using System.Threading.Tasks;
    using IdentityServer4.Services;
    using Ironclad.Custom;
    using Ironclad.Models;
    using Ironclad.Sdk;
    using Microsoft.AspNetCore.Mvc;

    [SecurityHeaders]
    public class HomeController : Controller
    {
        private static readonly object Version =
            new VersionModel
            {
                Title = typeof(Program).Assembly.Attribute<AssemblyTitleAttribute>(attribute => attribute.Title),
                Version = typeof(Program).Assembly.Attribute<AssemblyInformationalVersionAttribute>(attribute => attribute.InformationalVersion),
                OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription.TrimEnd(),
            };

        private readonly IIdentityServerInteractionService interaction;

        public HomeController(IIdentityServerInteractionService interaction)
        {
            this.interaction = interaction;
        }

        public IActionResult Index() => this.View(Version);

        public IActionResult About() => this.View();

        [Route("/signin/error")]
        public async Task<IActionResult> Error(string errorId)
        {
            var model = new ErrorModel();

            var message = await this.interaction.GetErrorContextAsync(errorId);
            if (message != null)
            {
                model.Error = message;
            }

            return this.View("Error", model);
        }
    }
}
