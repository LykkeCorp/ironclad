// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

namespace Ironclad.Controllers
{
    using System;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using Ironclad.Application;
    using Ironclad.Models;
    using Ironclad.Sdk;
    using Ironclad.Services.Email;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;

    [Authorize]
    [SecurityHeaders]
    public class ManageController : Controller
    {
        private const string AuthenicatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IEmailSender emailSender;
        private readonly ILogger logger;
        private readonly UrlEncoder urlEncoder;

        public ManageController(
          UserManager<ApplicationUser> userManager,
          SignInManager<ApplicationUser> signInManager,
          IEmailSender emailSender,
          ILogger<ManageController> logger,
          UrlEncoder urlEncoder)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.emailSender = emailSender;
            this.logger = logger;
            this.urlEncoder = urlEncoder;
        }

        [TempData]
        public string StatusMessage { get; set; }

        [Route("/settings/profile")]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var model = new IndexModel
            {
                Id = user.Id,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                FullName = user.FullName,
                PhoneNumber = user.PhoneNumber,
                IsEmailConfirmed = user.EmailConfirmed,
                StatusMessage = this.StatusMessage
            };

            return this.View(model);
        }

        [Route("/settings/profile")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(IndexModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            // TODO: implement update fields logic
//            var email = user.Email;
//            if (model.Email != email)
//            {
//                var setEmailResult = await this.userManager.SetEmailAsync(user, model.Email);
//                if (!setEmailResult.Succeeded)
//                {
//                    throw new ApplicationException($"Unexpected error occurred setting email for user with ID '{user.Id}'.");
//                }
//            }
//
//            var phoneNumber = user.PhoneNumber;
//            if (model.PhoneNumber != phoneNumber)
//            {
//                var setPhoneResult = await this.userManager.SetPhoneNumberAsync(user, model.PhoneNumber);
//                if (!setPhoneResult.Succeeded)
//                {
//                    throw new ApplicationException($"Unexpected error occurred setting phone number for user with ID '{user.Id}'.");
//                }
//            }

            this.StatusMessage = "Your profile has been updated";
            return this.RedirectToAction(nameof(this.Index));
        }

        [Route("/settings/profile/email/verify")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SendVerificationEmail(IndexModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var code = await this.userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = this.Url.EmailConfirmationLink(user.Id, code, this.Request.Scheme);
            var email = user.Email;
            await this.emailSender.SendEmailConfirmationAsync(email, callbackUrl);

            this.StatusMessage = "Verification email sent. Please check your email.";
            return this.RedirectToAction(nameof(this.Index));
        }

        [Route("/settings/changepassword")]
        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var hasPassword = await this.userManager.HasPasswordAsync(user);
            if (!hasPassword)
            {
                return this.RedirectToAction(nameof(this.SetPassword));
            }

            var model = new ChangePasswordModel { StatusMessage = this.StatusMessage };
            return this.View(model);
        }

        [Route("/settings/changepassword")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var changePasswordResult = await this.userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                this.AddErrors(changePasswordResult);
                return this.View(model);
            }

            await this.signInManager.SignInAsync(user, isPersistent: false);
            this.logger.LogInformation("this.User changed their password successfully.");
            this.StatusMessage = "Your password has been changed.";

            return this.RedirectToAction(nameof(this.ChangePassword));
        }

        [Route("/settings/setpassword")]
        [HttpGet]
        public async Task<IActionResult> SetPassword()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var hasPassword = await this.userManager.HasPasswordAsync(user);

            if (hasPassword)
            {
                return this.RedirectToAction(nameof(this.ChangePassword));
            }

            var model = new SetPasswordModel { StatusMessage = this.StatusMessage };
            return this.View(model);
        }

        [Route("/settings/setpassword")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SetPassword(SetPasswordModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var addPasswordResult = await this.userManager.AddPasswordAsync(user, model.NewPassword);
            if (!addPasswordResult.Succeeded)
            {
                this.AddErrors(addPasswordResult);
                return this.View(model);
            }

            await this.signInManager.SignInAsync(user, isPersistent: false);
            this.StatusMessage = "Your password has been set.";

            return this.RedirectToAction(nameof(this.SetPassword));
        }

        [Route("/settings/logins")]
        [HttpGet]
        public async Task<IActionResult> ExternalLogins()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var model = new ExternalLoginsModel { CurrentLogins = await this.userManager.GetLoginsAsync(user) };
            model.OtherLogins = (await this.signInManager.GetExternalAuthenticationSchemesAsync())
                .Where(auth => model.CurrentLogins.All(ul => auth.Name != ul.LoginProvider))
                .ToList();
            model.ShowRemoveButton = await this.userManager.HasPasswordAsync(user) || model.CurrentLogins.Count > 1;
            model.StatusMessage = this.StatusMessage;

            return this.View(model);
        }

        [Route("/settings/logins/link")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LinkLogin(string provider)
        {
            // Clear the existing external cookie to ensure a clean login process
            await this.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            // Request a redirect to the external login provider to link a login for the current user
            var redirectUrl = this.Url.Action(nameof(this.LinkLoginCallback));
            var properties = this.signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, this.userManager.GetUserId(this.User));
            return new ChallengeResult(provider, properties);
        }

        [Route("/settings/logins/link")]
        [HttpGet]
        public async Task<IActionResult> LinkLoginCallback()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var info = await this.signInManager.GetExternalLoginInfoAsync(user.Id);
            if (info == null)
            {
                throw new ApplicationException($"Unexpected error occurred loading external login info for user with ID '{user.Id}'.");
            }

            var result = await this.userManager.AddLoginAsync(user, info);
            if (!result.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occurred adding external login for user with ID '{user.Id}'.");
            }

            // Clear the existing external cookie to ensure a clean login process
            await this.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            this.StatusMessage = "The external login was added.";
            return this.RedirectToAction(nameof(this.ExternalLogins));
        }

        [Route("/settings/logins/remove")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveLogin(RemoveLoginModel model)
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var result = await this.userManager.RemoveLoginAsync(user, model.LoginProvider, model.ProviderKey);
            if (!result.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occurred removing external login for user with ID '{user.Id}'.");
            }

            await this.signInManager.SignInAsync(user, isPersistent: false);
            this.StatusMessage = "The external login was removed.";
            return this.RedirectToAction(nameof(this.ExternalLogins));
        }

        [Route("/settings/2fa")]
        [HttpGet]
        public async Task<IActionResult> TwoFactorAuthentication()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var model = new TwoFactorAuthenticationModel
            {
                HasAuthenticator = await this.userManager.GetAuthenticatorKeyAsync(user) != null,
                Is2faEnabled = user.TwoFactorEnabled,
                RecoveryCodesLeft = await this.userManager.CountRecoveryCodesAsync(user),
            };

            return this.View(model);
        }

        [Route("/settings/2fa/disable")]
        [HttpGet]
        public async Task<IActionResult> Disable2faWarning()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            if (!user.TwoFactorEnabled)
            {
                throw new ApplicationException($"Unexpected error occurred disabling 2FA for user with ID '{user.Id}'.");
            }

            return this.View(nameof(this.Disable2fa));
        }

        [Route("/settings/2fa/disable")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Disable2fa()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var disable2faResult = await this.userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occurred disabling 2FA for user with ID '{user.Id}'.");
            }

            this.logger.LogInformation("this.User with ID {UserId} has disabled 2fa.", user.Id);
            return this.RedirectToAction(nameof(this.TwoFactorAuthentication));
        }

        [Route("/settings/2fa/enable")]
        [HttpGet]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var unformattedKey = await this.userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await this.userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await this.userManager.GetAuthenticatorKeyAsync(user);
            }

            var model = new EnableAuthenticatorModel
            {
                SharedKey = FormatKey(unformattedKey),
                AuthenticatorUri = this.GenerateQrCodeUri(user.UserName, unformattedKey)
            };

            return this.View(model);
        }

        [Route("/settings/2fa/enable")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(EnableAuthenticatorModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            // Strip spaces and hyphens
            var verificationCode = model.Code
                .Replace(" ", string.Empty, false, CultureInfo.InvariantCulture)
                .Replace("-", string.Empty, false, CultureInfo.InvariantCulture);

            var is2faTokenValid = await this.userManager.VerifyTwoFactorTokenAsync(user, this.userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
            if (!is2faTokenValid)
            {
                this.ModelState.AddModelError("model.Code", "Verification code is invalid.");
                return this.View(model);
            }

            await this.userManager.SetTwoFactorEnabledAsync(user, true);
            this.logger.LogInformation("this.User with ID {UserId} has enabled 2FA with an authenticator app.", user.Id);
            return this.RedirectToAction(nameof(this.GenerateRecoveryCodes));
        }

        [Route("/settings/2fa/reset")]
        [HttpGet]
        public IActionResult ResetAuthenticatorWarning() => this.View(nameof(this.ResetAuthenticator));

        [Route("/settings/2fa/reset")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetAuthenticator()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            await this.userManager.SetTwoFactorEnabledAsync(user, false);
            await this.userManager.ResetAuthenticatorKeyAsync(user);

            this.logger.LogInformation("this.User with id '{UserId}' has reset their authentication app key.", user.Id);

            return this.RedirectToAction(nameof(this.EnableAuthenticator));
        }

        [Route("/settings/2fa/recoverycodes")]
        [HttpGet]
        public async Task<IActionResult> GenerateRecoveryCodes()
        {
            var user = await this.userManager.GetUserAsync(this.User);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            if (!user.TwoFactorEnabled)
            {
                throw new ApplicationException($"Cannot generate recovery codes for user with ID '{user.Id}' as they do not have 2FA enabled.");
            }

            var recoveryCodes = await this.userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            var model = new GenerateRecoveryCodesModel { RecoveryCodes = recoveryCodes.ToArray() };

            this.logger.LogInformation("this.User with ID {UserId} has generated new 2FA recovery codes.", user.Id);

            return this.View(model);
        }

        private static string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }

            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

#pragma warning disable CA1308
            return result.ToString().ToLowerInvariant();
#pragma warning restore CA1308
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                this.ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private string GenerateQrCodeUri(string username, string unformattedKey) =>
            string.Format(
                CultureInfo.InvariantCulture,
                AuthenicatorUriFormat,
                this.urlEncoder.Encode("Ironclad"),
                this.urlEncoder.Encode(username),
                unformattedKey);
    }
}
