﻿// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad
{
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using Ironclad.Services.Email;

    public static class EmailSenderExtensions
    {
        public static Task SendEmailConfirmationAsync(this IEmailSender emailSender, string email, string link)
        {
            return emailSender.SendEmailAsync(
                email,
                "Confirm your email",
                $"Please confirm your account by clicking this link: <a href='{HtmlEncoder.Default.Encode(link)}'>link</a>");
        }

        public static Task SendActivationEmailAsync(this IEmailSender emailSender, string email, string link)
        {
            return emailSender.SendEmailAsync(
                email,
                "New user account",
                $"To get started please activate your account: <a href='{HtmlEncoder.Default.Encode(link)}'>link</a>");
        }
    }
}
