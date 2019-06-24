// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.WebApi
{
    using System;
    using System.Diagnostics;
    using System.Reflection;
    using Ironclad.Custom;
    using Microsoft.AspNetCore.Mvc;

    [Route("api")]
    public class RootController : Controller
    {
        private static readonly object Version =
            new
            {
                Title = typeof(Program).Assembly.Attribute<AssemblyTitleAttribute>(attribute => attribute.Title),
                Version = typeof(Program).Assembly.Attribute<AssemblyInformationalVersionAttribute>(attribute => attribute.InformationalVersion),
                OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription.TrimEnd(),
                ProcessId = Process.GetCurrentProcess().Id,
                Azure = Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") != null
                    ? new
                    {
                        InstanceId = Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID"),
                        SiteName = Environment.GetEnvironmentVariable("WEBSITE_SITE_NAME"),
                        Hostname = Environment.GetEnvironmentVariable("WEBSITE_HOSTNAME"),
                        SlotName = Environment.GetEnvironmentVariable("WEBSITE_SLOT_NAME"),
                    }
                    : null,
            };

        [HttpGet]
        public IActionResult Get() => this.Ok(Version);
    }
}
