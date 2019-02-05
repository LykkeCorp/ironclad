// Copyright (c) Lykke Corp.
// See the LICENSE file in the project root for more information.

using Ironclad.Data.Migrations;

#pragma warning disable CA1054

namespace Ironclad.Controllers
{
    using System;
    using System.Globalization;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using IdentityModel;
    using IdentityServer4.Extensions;
    using IdentityServer4.Services;
    using Ironclad.Application;
    using Ironclad.ExternalIdentityProvider.Persistence;
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
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IStore<IdentityProvider> store;
        private readonly IEmailSender emailSender;
        private readonly ILogger logger;
        private readonly IIdentityServerInteractionService interaction;
        private readonly WebsiteSettings websiteSettings;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IStore<IdentityProvider> store,
            IEmailSender emailSender,
            ILogger<AccountController> logger,
            IIdentityServerInteractionService interaction,
            WebsiteSettings websiteSettings)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.store = store;
            this.emailSender = emailSender;
            this.logger = logger;
            this.interaction = interaction;
            this.websiteSettings = websiteSettings;
        }

        [TempData]
        public string ErrorMessage { get; set; }

        [Route("/signin")]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            // clear the existing external cookie to ensure a clean login process
            await this.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            var context = await this.interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && (await this.signInManager.GetExternalAuthenticationSchemesAsync()).Any(p => string.Equals(p.Name, context.IdP, StringComparison.InvariantCultureIgnoreCase)))
            {
                return this.ExternalLogin(context.IdP, returnUrl);
            }

            if (!this.websiteSettings.ShowLoginScreen)
            {
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }

            this.ViewData["ReturnUrl"] = returnUrl;
            return this.View();
        }

        [Route("/signin")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model, string returnUrl = null)
        {
            this.ViewData["ReturnUrl"] = returnUrl;

            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            // this doesn't count login failures towards account lockout to enable password failures to trigger account lockout, set lockoutOnFailure: true
            var result = await this.signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                this.logger.LogInformation("User logged in.");
                return this.RedirectToLocal(returnUrl);
            }
            else if (result.RequiresTwoFactor)
            {
                return this.RedirectToAction(nameof(this.LoginWith2fa), new { returnUrl, model.RememberMe });
            }
            else if (result.IsLockedOut)
            {
                this.logger.LogWarning("User account locked out.");
                return this.RedirectToAction(nameof(this.Lockout));
            }
            else
            {
                this.ModelState.AddModelError("Password", "Invalid username or password");
                return this.View(model);
            }
        }

        [Route("/signin/2fa")]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2fa(bool rememberMe, string returnUrl = null)
        {
            // ensure the user has gone through the username & password screen first
            var user = await this.signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            this.ViewData["ReturnUrl"] = returnUrl;

            return this.View(new LoginWith2faModel { RememberMe = rememberMe });
        }

        [Route("/signin/2fa")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faModel model, bool rememberMe, string returnUrl = null)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{this.userManager.GetUserId(this.User)}'.");
            }

            var authenticatorCode = model.TwoFactorCode
                .Replace(" ", string.Empty, false, CultureInfo.InvariantCulture)
                .Replace("-", string.Empty, false, CultureInfo.InvariantCulture);

            var result = await this.signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, rememberMe, model.RememberMachine);
            if (result.Succeeded)
            {
                this.logger.LogInformation("User with ID {UserId} logged in with 2fa.", user.Id);
                return this.RedirectToLocal(returnUrl);
            }
            else if (result.IsLockedOut)
            {
                this.logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return this.RedirectToAction(nameof(this.Lockout));
            }
            else
            {
                this.logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                this.ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return this.View();
            }
        }

        [Route("/signin/recover")]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWithRecoveryCode(string returnUrl = null)
        {
            // ensure the user has gone through the username & password screen first
            var user = await this.signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            this.ViewData["ReturnUrl"] = returnUrl;

            return this.View();
        }

        [Route("/signin/recover")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeModel model, string returnUrl = null)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException($"Unable to load two-factor authentication user.");
            }

            var recoveryCode = model.RecoveryCode
                .Replace(" ", string.Empty, false, CultureInfo.InvariantCulture)
                .Replace("-", string.Empty, false, CultureInfo.InvariantCulture);

            var result = await this.signInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
            if (result.Succeeded)
            {
                this.logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                return this.RedirectToLocal(returnUrl);
            }
            else if (result.IsLockedOut)
            {
                this.logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                return this.RedirectToAction(nameof(this.Lockout));
            }
            else
            {
                this.logger.LogWarning("Invalid recovery code entered for user with ID {UserId}", user.Id);
                this.ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                return this.View();
            }
        }

        [Route("/signin/locked")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout() => this.View();

        [Route("/signin/error")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult LoginError() => this.View();

        [Route("/signup")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            this.ViewData["ReturnUrl"] = returnUrl;
            return this.View();
        }

        [Route("/signup")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model, string returnUrl = null)
        {
            this.ViewData["ReturnUrl"] = returnUrl;

            if (this.ModelState.IsValid)
            {
                var existingUser = await this.userManager.FindByNameAsync(model.Email);

                if (existingUser != null)
                {
                    this.ModelState.AddModelError(string.Empty, "User already exists");
                    return this.View(model);
                }

                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    FullName = $"{model.FirstName} {model.LastName}"
                };

                var result = await this.userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    this.logger.LogInformation("User created a new account with password.");

//                    var code = await this.userManager.GenerateEmailConfirmationTokenAsync(user);
//                    var callbackUrl = this.Url.EmailConfirmationLink(user.Id, code, this.Request.Scheme);
//                    await this.emailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);

                    await this.signInManager.SignInAsync(user, isPersistent: false);
                    this.logger.LogInformation("User created a new account with password.");
                    return this.RedirectToLocal(returnUrl);
                }

                this.AddErrors(result);
            }

            // if we got this far, something failed, redisplay form
            return this.View(model);
        }

        [Route("/signout")]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var model = await this.BuildLogoutViewModelAsync(logoutId);
            if (model.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then we don't need to show the prompt and can just log the user out directly
                return await this.Logout(model);
            }

            return this.View(model);
        }

        [Route("/signout")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel inputModel)
        {
            var model = await this.BuildLoggedOutViewModelAsync(inputModel.LogoutId);

            await this.signInManager.SignOutAsync();
            this.logger.LogInformation("User logged out.");

            // check if we need to trigger sign-out at an upstream identity provider
            if (model.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back to us after the user has logged out
                // this allows us to then complete our single sign-out processing
                string url = this.Url.Action(nameof(this.Logout), new { logoutId = model.LogoutId });

                // this triggers a redirect to the external provider for sign-out hack try/catch to handle social providers that throw
                return this.SignOut(new AuthenticationProperties { RedirectUri = url }, model.ExternalAuthenticationScheme);
            }

            return this.View("LoggedOut", model);
        }

        [Route("/signin/external")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // request a redirect to the external login provider.
            var redirectUrl = this.Url.Action(nameof(this.ExternalLoginCallback), "Account", new { returnUrl });
            var properties = this.signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return this.Challenge(properties, provider);
        }

        [Route("/signin/external/callback")]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            if (remoteError != null)
            {
                this.ErrorMessage = $"Error from external provider: {remoteError}";
                return this.RedirectToAction(nameof(this.Login));
            }

            var info = await this.signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return this.RedirectToAction(nameof(this.Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await this.signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                this.logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                return this.RedirectToLocal(returnUrl);
            }
            else if (result.IsLockedOut)
            {
                return this.RedirectToAction(nameof(this.Lockout));
            }

            // NOTE (Cameron): We're looking at external providers now so we need to check the domain name against the restricted domain name.
            var email = info.Principal.FindFirstValue(ClaimTypes.Email) ?? info.Principal.FindFirstValue(JwtClaimTypes.Email);
            if (this.websiteSettings.RestrictedDomains.Any() && email?.Contains('@', StringComparison.OrdinalIgnoreCase) == true)
            {
                // we can only do this if we have an email claim
                var domainName = email.Substring(email.IndexOf('@', StringComparison.OrdinalIgnoreCase) + 1);
                if (!this.websiteSettings.RestrictedDomains.Contains(domainName))
                {
                    this.logger.LogWarning("User {Sub} failed to log in with {Name} provider (no account).", info.ProviderKey, info.LoginProvider);

                    this.ViewData["Title"] = "Login Forbidden";
                    this.ViewData["Error"] = "You are unable to login to the system with this account. " +
                        $"In order to login you must use an account with one of the following domains: {string.Join(", ", this.websiteSettings.RestrictedDomains)}.";

                    return this.View(nameof(this.LoginError));
                }
            }

            // NOTE (Cameron): Supported claims for provisioning. I have no idea why some are mapped using the Microsoft nonsense.
            var emailVerified = info.Principal.FindFirstValue(JwtClaimTypes.EmailVerified);
            var phone = info.Principal.FindFirstValue(JwtClaimTypes.PhoneNumber);
            var phoneVerified = info.Principal.FindFirstValue(JwtClaimTypes.PhoneNumberVerified);

            var user = new ApplicationUser
            {
                Email = email,
                EmailConfirmed = bool.TryParse(emailVerified, out var emailVerifiedValue) ? emailVerifiedValue : false,
                PhoneNumber = phone,
                PhoneNumberConfirmed = bool.TryParse(phoneVerified, out var phoneVerifiedValue) ? phoneVerifiedValue : false,
            };

            var identityProvider = await this.store.SingleOrDefaultAsync(provider => string.Equals(provider.Name, info.LoginProvider, StringComparison.OrdinalIgnoreCase));
            if (identityProvider?.AutoProvision == true)
            {
                // NOTE (Cameron): When auto-provision is specified we always use a GUID for the username.
                user.UserName = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);

                var autoProvisionResult = await this.userManager.CreateAsync(user);
                if (autoProvisionResult.Succeeded)
                {
                    autoProvisionResult = await this.userManager.AddLoginAsync(user, info);
                    if (autoProvisionResult.Succeeded)
                    {
                        await this.signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
                        this.logger.LogInformation("User created an account using {Name} provider (auto-provisioned).", info.LoginProvider);
                        return this.RedirectToLocal(returnUrl);
                    }
                }

                // NOTE (Cameron): This should not happen.
                this.logger.LogWarning("User {Sub} failed to log in with {Name} provider (auto-provisioning failed).", info.ProviderKey, info.LoginProvider);

                this.ViewData["Title"] = "Login Failed";
                this.ViewData["Error"] = "This login attempt failed to successfully provision and sign-in the user.";

                return this.View(nameof(this.LoginError));
            }

            // The user does not have an account and auto-provision is not configured, so ask the user to create an account.
            this.ViewData["ReturnUrl"] = returnUrl;
            this.ViewData["LoginProvider"] = info.LoginProvider;

            return this.View(nameof(this.ExternalLogin), new ExternalLoginModel { Email = email });
        }

        [Route("/signin/external/callback")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginModel model, string returnUrl = null)
        {
            if (this.ModelState.IsValid)
            {
                // get the information about the user from the external login provider
                var info = await this.signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }

                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };

                var result = await this.userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await this.userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await this.signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
                        this.logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        return this.RedirectToLocal(returnUrl);
                    }
                }

                this.AddErrors(result);
            }

            this.ViewData["ReturnUrl"] = returnUrl;

            return this.View(nameof(this.ExternalLogin), model);
        }

        [Route("/settings/profile/email/confirm")]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var user = await this.userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");
            }

            var result = await this.userManager.ConfirmEmailAsync(user, code);
            return this.View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [Route("/signin/forgotpassword")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword() => this.View();

        [Route("/signin/forgotpassword")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.FindByEmailAsync(model.Email);
            if (user == null || !(await this.userManager.IsEmailConfirmedAsync(user)))
            {
                // don't reveal that the user does not exist or is not confirmed
                return this.RedirectToAction(nameof(this.ForgotPasswordConfirmation));
            }

            // for more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=532713
            var code = await this.userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = this.Url.ResetPasswordLink(user.Id, code, this.Request.Scheme);
            await this.emailSender.SendEmailAsync(model.Email, "Reset Password", $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
            return this.RedirectToAction(nameof(this.ForgotPasswordConfirmation));
        }

        [Route("/signin/forgotpassword/complete")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation() => this.View();

        [Route("/signin/resetpassword")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var model = new ResetPasswordModel { UserId = userId, Code = code };
            return this.View(model);
        }

        [Route("/signin/resetpassword")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                // don't reveal that the user does not exist
                return this.RedirectToAction(nameof(this.ResetPasswordConfirmation));
            }

            var result = await this.userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                // automatic sign in after password has been reset
                await this.signInManager.SignInAsync(user, false, "pwd");

                return this.RedirectToAction(nameof(this.ResetPasswordConfirmation));
            }

            this.AddErrors(result);
            return this.View(model);
        }

        [Route("/signin/resetpassword/complete")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation() => this.View();

        [Route("/signup/register")]
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> CompleteRegistration(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var user = await this.userManager.FindByIdAsync(userId);
            if (user == null)
            {
                // don't reveal that the user does not exist
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var isValidToken = await this.userManager.VerifyUserTokenAsync(user, this.userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", code);
            if (!isValidToken)
            {
                // don't reveal that the user does not exist
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var model = new CompleteRegistrationModel { UserId = userId, Username = user.UserName, Code = code };
            return this.View(model);
        }

        [Route("/signup/register")]
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CompleteRegistration(CompleteRegistrationModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return this.View(model);
            }

            var user = await this.userManager.FindByIdAsync(model.UserId);
            if (user == null)
            {
                // don't reveal that the user does not exist
                return this.RedirectToAction(nameof(this.CompleteRegistrationConfirmation));
            }

            var code = model.Code;

            if (model.Username != user.UserName)
            {
                var setUsernameResult = await this.userManager.SetUserNameAsync(user, model.Username);
                if (!setUsernameResult.Succeeded)
                {
                    this.ModelState.AddModelError("Username", setUsernameResult.Errors.FirstOrDefault()?.Description);
                    return this.View(model);
                }

                code = await this.userManager.GeneratePasswordResetTokenAsync(user);
            }

            var result = await this.userManager.ResetPasswordAsync(user, code, model.Password);
            if (!result.Succeeded)
            {
                this.AddErrors(result);
                return this.View(model);
            }

            // confirm email
            var emailConfirmationToken = await this.userManager.GenerateEmailConfirmationTokenAsync(user);
            await this.userManager.ConfirmEmailAsync(user, emailConfirmationToken);

            // automatic sign in after registration completed
            await this.signInManager.SignInAsync(user, false, "pwd");

            return this.RedirectToAction(nameof(this.CompleteRegistrationConfirmation));
        }

        [Route("/signup/register/complete")]
        [HttpGet]
        [AllowAnonymous]
        public IActionResult CompleteRegistrationConfirmation() => this.View();

        [Route("/signin/denied")]
        [HttpGet]
        public IActionResult AccessDenied() => this.View();

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                this.ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (this.Url.IsLocalUrl(returnUrl))
            {
                return this.Redirect(returnUrl);
            }
            else
            {
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        private async Task<LogoutModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var model = new LogoutModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            var user = this.HttpContext.User;
            if (user?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                model.ShowLogoutPrompt = false;
                return model;
            }

            var context = await this.interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                model.ShowLogoutPrompt = false;
                return model;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return model;
        }

        private async Task<LoggedOutModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await this.interaction.GetLogoutContextAsync(logoutId);

            var model = new LoggedOutModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = logout?.ClientId,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            var user = this.HttpContext.User;
            if (user?.Identity.IsAuthenticated == true)
            {
                var idp = user.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await this.HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (model.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            model.LogoutId = await this.interaction.CreateLogoutContextAsync();
                        }

                        model.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return model;
        }
    }
}
