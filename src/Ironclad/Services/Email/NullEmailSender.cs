﻿// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Services.Email
{
    using System.Threading.Tasks;

    public class NullEmailSender : IEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string body) => Task.CompletedTask;
    }
}
