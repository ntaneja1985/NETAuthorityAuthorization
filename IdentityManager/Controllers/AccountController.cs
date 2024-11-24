using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using System.Text.Encodings.Web;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;
        public AccountController(SignInManager<ApplicationUser> signInManager,UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IEmailSender emailSender, UrlEncoder urlEncoder )
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
            _roleManager = roleManager;
        }
        [AllowAnonymous]
        public async Task<IActionResult> Register(string returnUrl = null)
        {
            if (!_roleManager.RoleExistsAsync(SD.Admin).GetAwaiter().GetResult())
            {
                await _roleManager.CreateAsync(new IdentityRole(SD.Admin));
                await _roleManager.CreateAsync(new IdentityRole(SD.User));
            }
           
            
            //list.Add(new SelectListItem() { Value = SD.Admin, Text = SD.Admin });
            //list.Add(new SelectListItem() { Value = SD.User, Text = SD.User });
            ViewBag.ReturnUrl = returnUrl;
            RegisterViewModel model = new RegisterViewModel()
            { RoleList = _roleManager.Roles.Select(x=>x.Name).Select(i=>
            new SelectListItem 
                { 
                    Value = i, 
                    Text = i
                })
            };
           
            return View(model);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerViewModel.Email,
                    Email = registerViewModel.Email,
                    Name = registerViewModel.Name,
                    DateCreated = DateTime.Now
                };

                var result = await _userManager.CreateAsync(user, registerViewModel.Password);
                if (result.Succeeded)
                {
                    if(registerViewModel.RoleSelected != null)
                    {
                        await _userManager.AddToRoleAsync(user, registerViewModel.RoleSelected);
                    } else
                    {
                        await _userManager.AddToRoleAsync(user, SD.User);
                    }
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.Action("ConfirmEmail", "Account",
                    new { userId = user.Id, code = code },
                    protocol: HttpContext.Request.Scheme);
                    await _emailSender.SendEmailAsync(user.Email, "Confirm Email",
                    $"Please confirm your email by clicking here: <a href='{callbackUrl}'>link</a>");

                    await _signInManager.SignInAsync(user, false);
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnUrl);
                }

                AddErrors(result);
            }
            registerViewModel.RoleList = _roleManager.Roles.Select(x => x.Name).Select(i =>
             new SelectListItem
             {
                 Value = i,
                 Text = i
             });

            return View(registerViewModel);
        }

        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {

                var result = await _signInManager.PasswordSignInAsync(model.Email,model.Password,
                    model.RememberMe,lockoutOnFailure:true);
                if (result.Succeeded)
                {
                    var user = await _userManager.GetUserAsync(User);
                    var claim = await _userManager.GetClaimsAsync(user);

                    if(claim.Count > 0)
                    {
                        var specificClaim = claim.FirstOrDefault(u => u.Type == "FirstName");
                        if (specificClaim != null)
                        {
                            await _userManager.RemoveClaimAsync(user, specificClaim);
                        }
                    }
                    await _userManager.AddClaimAsync(user, new System.Security.Claims.Claim("FirstName",user.Name));
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnUrl);
                }
                else if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new {returnUrl = returnUrl, rememberMe =  model.RememberMe});
                }
                else if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
                    return View(model);
                }
               
            }
            return View(model);
        }

     
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConfirmation");
                }

                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Account", 
                    new { userid = user.Id, code = code },
                    protocol:HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Reset Password",
                    $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
                
                return RedirectToAction(nameof(ForgotPasswordConfirmation));
            }
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }
                var result = await _userManager.ResetPasswordAsync(user,model.Code, model.Password);
                if(result.Succeeded)
                {
                    return RedirectToAction(nameof(ResetPasswordConfirmation));
                }
                AddErrors(result);
            }
            return View();
        }

        [HttpGet]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string code,string userId)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                {
                    return View("Error");
                }
                var result = await _userManager.ConfirmEmailAsync(user,code);
                if (result.Succeeded)
                {
                    return View();
                }
                
            }
            return View("Error");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }




        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Error()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult NoAccess()
        {
            return View();
        }



        #region TwoFactorAuthentication

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);

            string AuthUri = string.Format(AuthenticatorUriFormat,
                _urlEncoder.Encode("IdentityManager"), _urlEncoder.Encode(user.Email),token);
            
            var model = new TwoFactorAuthenticationViewModel() { Token = token, QrCodeUrl = AuthUri };
            
            return View(model);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, enabled: true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your two factor code could not be validated");
                    return View(model);
                }

                return RedirectToAction(nameof(AuthenticatorConfirmation));
            }
            return View("Error");

        }

        [HttpGet]
        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }



        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if(user == null)
            {
                return View("Error");
            }
            ViewBag.ReturnUrl = returnUrl;  

            return View(new VerifyAuthenticatorViewModel() { RememberMe = rememberMe, ReturnUrl = returnUrl});  

        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
        {
            var returnUrl = model.ReturnUrl;
            returnUrl = returnUrl ?? Url.Content("~/");
            if (!ModelState.IsValid) 
            {
                return View(model);
            }
            else
            {

                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code,
                     isPersistent: model.RememberMe,rememberClient: false);
                if (result.Succeeded)
                {
                    //return RedirectToAction("Index", "Home");
                    return LocalRedirect(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
                    return View(model);
                }

            }
        }

        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index), "Home");
        }

        #endregion

        private void AddErrors(IdentityResult result)
        {
            foreach(var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
