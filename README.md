# NETAuthorityAuthorization
.NET Authentication and Authorization


## ASP.NET Core Identity
- Fresh and modern look at the membership system
- Implemented as Razor class library in ASP.NET Core
- ASP.NET Core Identity is a user store and much more
- Requires Minimal knowledge of identity and security.
- Includes extensive helper methods that performs the essential core functionality in identity management development.
- Some of the helper functionality includes methods for password hashing, Password validation, Password reset,Confirmation,User lockout,Multi-factor authentication,Token generation,External identity providers and much more.
- Net core identity has many helper methods around authentication, but do not confuse it as an authentication library. Authentication within your application is still handled by your authentication middleware like cookies
or OpenID connect middleware.
- .Net identity may be used to verify the credentials, but this middleware libraries are responsible for authenticating each request in your application.
- Also, make a note and always remember that the.Net Core Identity Library and Identity Server are two different concepts and libraries.
- Identity server has been renamed to Duende Server that offers protocol support for OpenID connect, whereas the.Net core identity is your user store.
- Identity Server is an authentication server that implements OAuth 2.0 and Open ID Connect(OIDC)
- Great question! Here's a concise comparison between ASP.NETCore Identity and IdentityServer:

## ASP.NETCore Identity
- Purpose: Manages user authentication and authorization within your application.
- Features: Handles user registration, login, password management, roles, and claims.
- Use Case: Ideal for applications that need to manage user accounts and authentication internally2.
- Integration: Easily integrates with ASP.NETCore applications.

## IdentityServer
- Purpose: Provides an implementation of OpenID Connect and OAuth 2.0 protocols for authentication and authorization.
- Features: Supports Single Sign-On (SSO), token-based authentication, and API protection.
- Use Case: Suitable for applications that need to support multiple clients (e.g., web, mobile apps) and external identity providers.
- Integration: Can be used with ASP.NETCore Identity for user management, but also supports other identity providers.

## Key Differences
- Scope: ASP.NETCore Identity is focused on managing user accounts within your application, while IdentityServer is focused on providing authentication and authorization services for multiple clients and external identity providers3.
- Protocols: IdentityServer supports OpenID Connect and OAuth 2.0, which are standards for authentication and authorization, whereas ASP.NETCore Identity does not inherently support these protocols3.
- Flexibility: IdentityServer offers more flexibility for integrating with various external identity providers and supporting different types of clients (web, mobile, etc.), whereas ASP.NETCore Identity is more tightly integrated with ASP.NETCore applications.

## Authentication and Authorization
- Who you are is authentication and what access do you have is authorization

## Types of authentication
- Cookie based authentication: Default method for very long
- This authentication is stateful
- Server needs to keep track of active sessions in the database and on the front-end a cookie is created that holds a session identifier and hence the name cookie based authentication
- We also have token based authentication
- More recent
- Used with SPA and IOT
- Done using JWT
- Here server doesnot keep track of which users are logged in, each request to the server is accompanied with a token which the server can then use to identify the user
- Token based authentication is stateless
- Cookie based authentication is used when we have username and password in our website
- Token based authentication may use external login for authentication like using Google or Facebook for login
- We are redirected to Facebook website where we login and then we are redirected to web app with a token

- ## Cookie based vs Token based
- ### Flow of Cookie based authentication
- In Cookie based, initially the user enters their username and password
- Server verifies the credentials are correct and then it creates a session which is stored in the database and then inside a cookie
- A cookie with the session Id is placed in the user's browser with a certain expiration time
- On subsequent requests, session Id is verified against a database
- If user logouts of the app, the session is destroyed both client-side and server-side
- ### Flow of Token based authentication
- User enters their login credentials
- Server verifies if credentials are valid and it returns a signed token
- This token is stored client side either in local storage or in a HTTP Only Cookie
- Subsequent requests to the server will include this token
- When server receives the token, it will decode the JWT and if the token is valid
- Once the user logouts, the token is destroyed in the client side.
- Token based authentication is more common in mobile apps and SPAs
- Cookie based is more common in server to server communication

## ASP.NET Identity Structure and Architecture
- Main goal is user store and user management
- User store and Role Store (DAL): They abstract away the underlying database
- This store allows us to change database providers
- Next layer is the managers like User Manager & Role Manager: Here all business logic lives: hashing password, managing users
- They are like the gateway in .Net Core Identity Library
- ![alt text](image.png)
- Final Layer is library of methods that support out of the box integration with external library
- Example is Sign In Manager
- Underlying all of this is a common set of entities like user, role and user-role
- We will use EFCore IdentityDbContext to use these entities.

## 2 types of authorization
- Role based authorization like customer, manager, admin, front desk etc
- Based on role, we determine what access they have
- Claims based authorization: This is a piece of information about a user
- It can be gender, email
- Customer with more than 20 bookings as elite customer
- We can use that claim to give that customer some special privileges
- Claims are like key-value pairs
- Roles are just keys
- We can use a combination of claims and roles to grant access

## Install Microsoft.AspnetCore.Identity.EntityFrameworkCore
- Once we install this package, we need to configure ApplicationDbContext as follows:
```c#
public class ApplicationDbContext:IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions options) : base(options) 
        { 

        }
    }
```
- We also need to setup Program.cs to use SqlServer
```c#
builder.Services.AddDbContext<ApplicationDbContext>(
    options => options.UseSqlServer(builder
    .Configuration.GetConnectionString("DefaultConnection")));

```
- Next add a package called EntityFramework.Core.Tools
- Open Package Manager Console and add the migration
```shell
add-migration AddIdentityTables
```
- It will add tables such as AspNetCoreUsers, AspNetCoreRoles, AspNetCoreClaims etc.
- Next we need to add Identity Service to our application and configure it to use EntityFrameworkStores we have configured like this:
```c#
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

```
- To Add more columns to the AspNetUsers table, we can go to Models folder and add an ApplicationUser like this:
```c#
public class ApplicationUser:IdentityUser
{
    [Required]
    public string Name { get; set; }

}
```
- Then if we add migration, we will see not one but 2 columns being added: Discriminator and Name
- Then we need to add views for Login and Register. First we will setup the ViewModels as follows:
```c#
public class RegisterViewModel
{
    [Required]
    public string Name { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Password")]
    [StringLength(100,ErrorMessage = "The {0} must be atleast {2} characters long",MinimumLength = 6)]
    public string Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Display(Name="Confirm Password")]
    [Compare("Password",ErrorMessage = "The password and confirm password donot match")]
    public string ConfirmPassword { get; set; }

}
```

- Next step is to add the view for Register like this:
```html
@model RegisterViewModel

<div class="row col-md-10 offset-md-1">
    <h1 class="text-primary text-center pt-2">
        Register
    </h1>
    <form method="post" asp-controller="Account" asp-action="Register">
        <div class="border p-2 rounded">
            <p class="text-center">Create a new Account</p>
            <div asp-validation-summary="All" class="text-danger"></div>
            <div class="form-group">
                <label asp-for="Email" class="col-12"></label>
                <div class="col-md-12">
                    <input asp-for="Email" class="form-control"/>
                    <span asp-validation-for="Email" class="text-danger"></span>
                </div>
            </div>
            <div class="form-group">
                <label asp-for="Name" class="col-12"></label>
                <div class="col-md-12">
                    <input asp-for="Name" class="form-control" />
                    <span asp-validation-for="Name" class="text-danger"></span>
                </div>
            </div>
            <div class="form-group">
                <label asp-for="Password" class="col-12"></label>
                <div class="col-md-12">
                    <input asp-for="Password" class="form-control" />
                    <span asp-validation-for="Password" class="text-danger"></span>
                </div>
            </div>
            <div class="form-group">
                <label asp-for="ConfirmPassword" class="col-12"></label>
                <div class="col-md-12">
                    <input asp-for="ConfirmPassword" class="form-control" />
                    <span asp-validation-for="ConfirmPassword" class="text-danger"></span>
                </div>
            </div>
            <div class="form-group pt-3">
                
                <div class="col-md-6 offset-md-3">
                   <button class="btn btn-success form-control" type="submit">Register</button>
                </div>
            </div>
        </div>
    </form>
</div>

@section Scripts {
    @{
        await Html.RenderPartialAsync("_ValidationScriptsPartial");
    }
}

```
## Handling Registration
- Registration is done using 2 Helper Classes: User Manager and SignIn Manager
  
```c#
using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        public AccountController(SignInManager<IdentityUser> signInManager,UserManager<IdentityUser> userManager )
        {
            _signInManager = signInManager;
            _userManager = userManager;
        }
        public IActionResult Register()
        {
            RegisterViewModel model = new RegisterViewModel();
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerViewModel.Email,
                    Email = registerViewModel.Email,
                    Name = registerViewModel.Name
                };

                var result = await _userManager.CreateAsync(user, registerViewModel.Password);
                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, false);
                    return RedirectToAction("Index", "Home");
                }
            }
            return View(registerViewModel);
        }
    }
}

```
- The Discriminator column displays whether the user is an Identity User or Application User, it holds the type of user

## Handling Errors

```c#
  public async Task<IActionResult> Register(RegisterViewModel registerViewModel)
  {
      if (ModelState.IsValid)
      {
          var user = new ApplicationUser
          {
              UserName = registerViewModel.Email,
              Email = registerViewModel.Email,
              Name = registerViewModel.Name
          };

          var result = await _userManager.CreateAsync(user, registerViewModel.Password);
          if (result.Succeeded)
          {
              await _signInManager.SignInAsync(user, false);
              return RedirectToAction("Index", "Home");
          }

          AddErrors(result);
      }
      return View(registerViewModel);
  }

  private void AddErrors(IdentityResult result)
  {
      foreach(var error in result.Errors)
      {
          ModelState.AddModelError(string.Empty, error.Description);
      }
  }
```

## Displaying SignedIn  User
- Here note that in the partial view, we are injecting the SignInManager and UserManager
- Also once, we sign in using AspNetCoreIdentity, it sets a special kind of claim 'User' which we can use to access various properties of the SignedIn User
```c#
@using Microsoft.AspNetCore.Identity

@inject SignInManager<IdentityManager.Models.ApplicationUser> SignInManager
@inject UserManager<IdentityManager.Models.ApplicationUser> UserManager


<ul class="navbar-nav">
    @if (SignInManager.IsSignedIn(User))
    {
        <li class="nav-item">
            <a class="nav-link" href="#">@UserManager.GetUserName(User)</a>
        </li>
        <li class="nav-item">
            <form id="logoutForm" method="post" class="form-inline" asp-controller="Account" asp-action="Logout">
                <button type="submit" class="btn nav-link">Logout</button>
            </form>
        </li>
    }
    else
    {
        <li class="nav-item">
            <a class="nav-link" asp-controller="Account" asp-action="Register">Register</a>
        </li>
        <li class="nav-item">
            <a class="nav-link" asp-controller="Account" asp-action="Login">Login</a>
        </li>
    }
</ul>


```

## Handling Login of a User
```c#
 [HttpPost]
 [ValidateAntiForgeryToken]
 public async Task<IActionResult> Login(LoginViewModel model)
 {
     if (ModelState.IsValid)
     {

         var result = await _signInManager.PasswordSignInAsync(model.Email,model.Password,model.RememberMe,lockoutOnFailure:false);
         if (result.Succeeded)
         { 
             return RedirectToAction("Index", "Home");
         }
         else
         {
             ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
             return View(model);
         }
        
     }
     return View(model);
 }
```

## Handling Logout of a User
```c#
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Logout()
{
    await _signInManager.SignOutAsync();
    return RedirectToAction("Index", "Home");
}
```

## Handling Url Redirects
- Lets say a user is not logged in and tries to access a page, he will be redirected to login page
- Once the user has successfully logged in, we want him to go back to the same page he was trying to login from
```c#
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
{
    ViewBag.ReturnUrl = returnUrl;
    returnUrl = returnUrl ?? Url.Content("~/");
    if (ModelState.IsValid)
    {

        var result = await _signInManager.PasswordSignInAsync(model.Email,model.Password,model.RememberMe,lockoutOnFailure:false);
        if (result.Succeeded)
        { 
            //return RedirectToAction("Index", "Home");
            return LocalRedirect(returnUrl);
        }
        else
        {
            ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
            return View(model);
        }
       
    }
    return View(model);
}
```
## Default Password Requirements
- If a user makes a specified number of unsuccessful logins, we can lockout the user
- We have 2 columns in AspNetCoreUsers table: LockoutEnd and AccessFailedCount
- Configuring Password options can be done in Program.cs file here:
  ```c#
    builder.Services.Configure<IdentityOptions>(
    opt => {
        opt.Password.RequireDigit = false;
        opt.Password.RequireLowercase = false;
        opt.Password.RequireNonAlphanumeric = false;
    });
  ```
  ## Configuring Lockout
  - In AspnetUsers table, we have LockoutEnd DateTime field
  - If the user fails to login in 3 attempts, he will be locked out and we can setup a view to show to the user that he is locked out
  - We can configure lockout options like this
  ```c#
    builder.Services.Configure<IdentityOptions>(
    opt => {
        opt.Password.RequireDigit = false;
        opt.Password.RequireLowercase = false;
        opt.Password.RequireNonAlphanumeric = false;
        opt.Lockout.MaxFailedAccessAttempts = 3;
        opt.SignIn.RequireConfirmedEmail = false;
        opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    });
  ```

  ## Configuring Send Grid 
  - Configure it like this:
  - ![alt text](image-1.png)
  - Install Nuget Package
  - ![alt text](image-2.png)
  - Now setup EmailSender.cs file like this
  
    ```c#
    using Microsoft.AspNetCore.Identity.UI.Services;
    using SendGrid.Helpers.Mail;
    using SendGrid;

    namespace IdentityManager.Services
    {
    public class EmailSender : IEmailSender
    {
        public string SendGridKey { get; set; }
        public EmailSender(IConfiguration _config) 
        {
            SendGridKey = _config.GetValue<string>("SendGrid:SecretKey");
        }
        public  Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var client = new SendGridClient(SendGridKey);
            var from_email = new EmailAddress("test@example.com", "Example User");
            var to_email = new EmailAddress(email);
            var msg = MailHelper.CreateSingleEmail(from_email, to_email, subject, "", htmlMessage);
            return client.SendEmailAsync(msg);
            }
        }
    }
    ```
## Reset Password Token
  - If the user forgets his password, we generate a token and send him a password reset link
  ```c#
    [HttpPost]
    [ValidateAntiForgeryToken]
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
  ```

- Also note, generating tokens will not work, till we first setup DefaultTokenProviders
```c#
    builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
```
- Next when we receive the code in the email, we will need to show the user a Reset Password Screen with ability to enter a new password
- Once we enter the new password, we will need to pass in the token which he received in his email, validate it and then reset the password
```c#
    [HttpPost]
    [ValidateAntiForgeryToken]
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

```
- Once the password has been reset we redirect the user to a Reset Password Confirmation View

## Confirm Email
- In AspnetUser, we have a column EmailConfirmed
- We can send a link to the user to confirm email, if confirmed, it will set this EmailConfirmed flag to true
- We need to generate a token for Email Confirmation 
```c#
[HttpPost]
[ValidateAntiForgeryToken]
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
            Name = registerViewModel.Name
        };

        var result = await _userManager.CreateAsync(user, registerViewModel.Password);
        if (result.Succeeded)
        {
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
    return View(registerViewModel);
}
```
- Next we need to validate this token when the user clicks on the link in the email, and then set the EmailConfirmed flag to true

```c#
    [HttpGet]
[ValidateAntiForgeryToken]
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

```

# Two-Factor Authentication

## Enable Authenticator Get Endpoint
- Two Factor authentication involves generating a code and sending it to the mobile phone of user using the Google Authenticator App or Microsoft Authenticator App
- The user gets the code on the app and enters on the app screen
- We will display a link to the user to setup 2 factor authenticator.
- First step is to generate the token for the user:
```c#
 [HttpGet]
[Authorize]
public async Task<IActionResult> EnableAuthenticator()
{
    var user = await _userManager.GetUserAsync(User);
    await _userManager.ResetAuthenticatorKeyAsync(user);
    var token = await _userManager.GetAuthenticatorKeyAsync(user);
    var model = new TwoFactorAuthenticationViewModel() { Token = token };
    return View(model);
}

```
- Next step is to display some UI to the user with the token and a textbox to enter the code
- To do this first we need to setup the ViewModel for 2 Factor Authentication
```c#
    public class TwoFactorAuthenticationViewModel
{
    public string Code { get; set; }
    public string Token { get; set; }
}
```
- Next step is to verify the token(code) entered by the user
```c#
    [HttpPost]
[Authorize]
[ValidateAntiForgeryToken]
public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
{
    if(ModelState.IsValid)
    {
        var user = await _userManager.GetUserAsync(User);
        var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user,_userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
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

```
- The above code will then enable the Two Factor Authentication for the user. There is a column Two Factor enabled in AspNetUsers table which will be set to true
- Next time the user logs in, he will be required to first sign in using his password and then using the 2 factor code.

## Setup Two Factor Auth on Account
- ![alt text](image-3.png)
- ![alt text](image-4.png)
- First the user will be required to go the Verify Authenticator Page once he has entered his password:
```c#
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
```
- Once the user enters the code from the Authenticator App, his code will be verified and if it is correct, the user is logged in
```c#
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

```
## Setup the QR Code for 2 factor authentication
- Go to this website: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-enable-qrcodes?view=aspnetcore-9.0
- Download QrCode.js from this site: https://davidshimjs.github.io/qrcodejs/
- Put the QrCode.js inside the js folder in wwwroot
- Modify the Enable Authenticator Code like this to generate the AuthenticatorUri
```c#
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

```

- Display QRCode on Enable Authenticator View like this
  
```c#
    @model TwoFactorAuthenticationViewModel

        <div class="row col-md-10 offset-md-1">
        <h1 class="text-primary text-center pt-2">
        Enable Authenticator
        </h1>
        <form method="post">
            <div class="border p-2 rounded">
            <p class="text-center">Please enter the code below in your authenticator App</p>
            <p class="text-center">@Model.Token</p>
            <p class="text-center">
                Alternatively, scan the below QR Code with your mobile phone
            </p>
            <div class="text-center" id="qrcode">

            </div>
            <div asp-validation-summary="All" class="text-danger"></div>
            <div class="form-group">
                <label asp-for="Code" class="col-12"></label>
                <div class="col-md-12">
                    <input asp-for="Code" class="form-control" />
                    <span asp-validation-for="Code" class="text-danger"></span>
                </div>
            </div>

            <div class="form-group pt-3">

                <div class="col-md-6 offset-md-3">
                    <button class="btn btn-success form-control" type="submit">Submit</button>
                </div>
            </div>
        </div>
    </form>
</div>

@section Scripts {
    @{
        <script src="~/js/qrcode.js"></script>
        <script type="text/javascript">
            new QRCode(document.getElementById("qrcode"), "@Model.QrCodeUrl");
        </script>
        await Html.RenderPartialAsync("_ValidationScriptsPartial");
        }
    }

  ```
-  Also remember that if the user has 2 factor authentication enabled, after he signs in with his username/password redirect him to VerifyAuthenticator Page
  
  ```c#
    [HttpPost]
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

  ```
## Reset Two Factor Authentication
- We also have the option to reset the 2 factor Authentication
- First we need to setup the view. If the user has successfully logged in, he has the option to remove the 2 factor authentication
```c#

@{
    ViewData["Title"] = "Home Page";
}

<div class="text-center">
    <h1 class="display-4">Welcome</h1>
    @if(User.Identity.IsAuthenticated)
    {
        var twoFactor = ViewBag.TwoFactorEnabled;
        if (twoFactor != null && twoFactor.ToString().ToLower() == "true")
        {
            <a asp-action="RemoveAuthenticator" asp-controller="Account" class="btn btn-warning">Reset and Remove 2 Factor Authentication</a>
            <br />
        }
        else {
            <a asp-action="EnableAuthenticator" asp-controller="Account">Setup 2 Factor Authenticator</a>
            <br/>
        }
    }
    <p>Learn about <a href="https://learn.microsoft.com/aspnet/core">building Web apps with ASP.NET Core</a>.</p>
    </div>

```
- Then if we clicks on Remove Authentication then the following code is executed and the user will have to setup 2 factor authentication again.
- ![alt text](image-5.png)
```c#
 [HttpGet]
 public async Task<IActionResult> RemoveAuthenticator()
 {
     var user = await _userManager.GetUserAsync(User);
     await _userManager.ResetAuthenticatorKeyAsync(user);
     await _userManager.SetTwoFactorEnabledAsync(user, false);
     return RedirectToAction(nameof(Index), "Home");
 }
```

# Authorization
- Use the [Authorize] annotation
- If the user tries to go to an action endpoint with authorize endpoint and he is not logged in, he is taken to the sign in page
- We can enhance this with roles and claims
- We can add this annotation at controller level also
- This will make sure that all action methods inside a controller can be accessed by authorized users only
- However, if we want to exclude any method from authorization inside this controller, we can use [AllowAnonymous] annotation
- Method Level annotations take precedence over Controller Level Annotations
- To create roles, we need to use Role Manager
- When the user registers, we will show him a list of roles and allow him to select roles
```c#

    //Creating Roles
  public async Task<IActionResult> Register(string returnUrl = null)
  {
      if (!_roleManager.RoleExistsAsync(SD.Admin).GetAwaiter().GetResult())
      {
          await _roleManager.CreateAsync(new IdentityRole(SD.Admin));
          await _roleManager.CreateAsync(new IdentityRole(SD.User));
      }
     
      
    //Adding roles dynamically
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

  //Adding Roles for a user
   if(registerViewModel.RoleSelected != null && registerViewModel.RoleSelected.Length > 0 && registerViewModel.RoleSelected == SD.Admin)
 {
     await _userManager.AddToRoleAsync(user, SD.Admin);
 } else
 {
     await _userManager.AddToRoleAsync(user, SD.User);
 }
```
- To ensure a functionality is accessible for a certain role use this
```c#
 [Authorize(Roles = SD.Admin)]
 public IActionResult Privacy()
 {
     return View();
 }
```
- If a user is not logged in, we may need to redirect them to an Access Denied Page.
- This is set inside an application cookie in Program.cs here:
```c#
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAccess");
});

```
## Role Management
- Just like SignInManager and UserManager, we have RolesManager which we can use to create/edit/delete roles
```c#
 public class RoleController : Controller
 {
     private readonly ApplicationDbContext _db;
     private readonly UserManager<ApplicationUser> _userManager;
     private readonly RoleManager<IdentityRole> _roleManager;

     public RoleController(ApplicationDbContext db, 
         UserManager<ApplicationUser> userManager,
         RoleManager<IdentityRole> roleManager)
     {
         _db = db;
         _userManager = userManager;
         _roleManager = roleManager;
     }
     public IActionResult Index()
     {
         var roles = _db.Roles.ToList();

          return View(roles);
     }

     [HttpGet]
     public IActionResult Upsert(string roleId)
     {
         if(string.IsNullOrEmpty(roleId))
         {
             //create
             return View();
         } else
         {
             //update
             var obj = _db.Roles.FirstOrDefault(x=>x.Id == roleId);
             return View(obj);
         }
     }

     [HttpPost]
     [ValidateAntiForgeryToken]
     public async Task<IActionResult> Delete(string roleId)
     {

        
             //delete
             var obj = _db.Roles.FirstOrDefault(x => x.Id == roleId);
         if (obj == null)
         {
             TempData[SD.Error] = "Role not found";
         }
         else
         {

             var userRoles = _db.UserRoles.Where(u => u.RoleId == roleId).Count();
             if (userRoles > 0)
             {
                 TempData[SD.Error] = "Role is associated with a user, so cannot delete";
             }
             else
             {
                 var result = await _roleManager.DeleteAsync(obj);
                 TempData[SD.Success] = "Role Deleted Successfully";
             }
             //var result = _db.Roles.Update(obj);
             //return View(obj);
         }
         
         return RedirectToAction(nameof(Index));
     }

     [HttpPost]
     [ValidateAntiForgeryToken]
     public async Task<IActionResult> Upsert(IdentityRole roleObj)
     {
         if (roleObj.Id == null && await _roleManager.RoleExistsAsync(roleObj.Name))
         {
             //role exists show error
         }
         if (string.IsNullOrEmpty(roleObj.NormalizedName))
         {
             //create
             await _roleManager.CreateAsync(new IdentityRole(roleObj.Name));
             TempData[SD.Success] = "Role Created Successfully";
             //return View();
         }
         else
         {
             //update
             var obj = _db.Roles.FirstOrDefault(x => x.Id == roleObj.Id);
             obj.Name = roleObj.Name;
             obj.NormalizedName = roleObj.Name.ToUpper();
             var result = await _roleManager.UpdateAsync(obj);
             TempData[SD.Success] = "Role updated Successfully";
             //var result = _db.Roles.Update(obj);
             //return View(obj);
         }
         return RedirectToAction(nameof(Index));
     }
 }
```

- To check user role in AspNetUserRoles table we can do this
```c#
public IActionResult Index()
{
    var usersList = _db.ApplicationUser.ToList();
    var userRole = _db.UserRoles.ToList();
    var roles = _db.Roles.ToList();

    foreach (var user in usersList)
    {
        var user_Role = userRole.FirstOrDefault(x=>x.UserId == user.Id);
        if (user_Role == null)
        {
            user.Role = "none";
        }
        else 
        {
            user.Role = roles.FirstOrDefault(u => u.Id == user_Role.RoleId).Name;
        }
    }
    return View(usersList);
}

```

## Assign Role to Users
- We need to Manage Roles for the User
- Earlier we saw how we could create CRUD operations related to Roles
- Now we need to show the roles currently assigned to a user and the list of roles available
- ![alt text](image-6.png)
- ![alt text](image-7.png)
- Following is the code for displaying the Manage Roles Screen
```c#
 [HttpGet]
 public async Task<IActionResult> ManageRole(string userId)
 {
     ApplicationUser user = await _userManager.FindByIdAsync(userId);
     if (user == null)
     {
         return NotFound();
     }
     List<string> existingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;
     var model = new RolesViewModel()
     {
         User = user
     };
     foreach (var role in _roleManager.Roles)
     {
         RoleSelection roleSelection = new()
         {
             RoleName = role.Name
         };
         if (existingUserRoles.Any(c => c == role.Name))
         {
             roleSelection.IsSelected = true;
         }
         model.RolesList.Add(roleSelection);
     }
     return View(model);
 }    
```
- For saving the role assignment we have the following code:
- We first remove all the existing roles and then add roles based on selection for the user
```c#
 [HttpPost]
public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
{
    ApplicationUser user = await _userManager.FindByIdAsync(rolesViewModel.User.Id);
    if (user == null)
    {
        return NotFound();
    }
  var oldUserRoles = await _userManager.GetRolesAsync(user);
    //Remove old roles
  var result = await _userManager.RemoveFromRolesAsync(user,oldUserRoles);

    if(!result.Succeeded)
    {
        TempData[SD.Error] = "Error while removing roles";
        return View(rolesViewModel);
    }

    result = await _userManager.AddToRolesAsync(user, 
        rolesViewModel.RolesList.Where(x => x.IsSelected).Select(x => x.RoleName));


    if (!result.Succeeded)
    {
        TempData[SD.Error] = "Error while adding roles";
        return View(rolesViewModel);
    }

    TempData[SD.Success] = "Roles assigned Successfully";
    return RedirectToAction(nameof(Index));
}
```
- Code for displaying the Manage Roles Screen is as follows:
```html
        
    @model RolesViewModel

<form method="post">
  <input asp-for="@Model.User.Id" hidden/>
<br/>
<div class="card shadow border-0 mt-4">
    <div class="card-header bg-success bg-gradient m-lg-0 py-3">
        <div class="row">
            <div class="col-12 text-center">
                <h2 class="text-white py-2">Manage User Roles</h2>
            </div>

        </div>
    </div>
    <div class="card-body p-4">
            <div class="border p-2 rounded">
               
                <div class="form-group">
                    <label class="col-12">User Name</label>
                    <div class="col-md-12">
                        <input asp-for="User.Name" disabled class="form-control" />     
                    </div>
                </div>
                <div class="form-group">
                    <label class="col-12">User Email</label>
                    <div class="col-md-12">
                        <input asp-for="User.Email" disabled class="form-control" />
                    </div>
                </div>

                <div class="form-group mt-3 p-2 border rounded">
                    <span>Roles Assignment</span>
                    @for(int i = 0; i<Model.RolesList.Count;i++)
                    {
                        <div class="m-2 form-check">
                            <input asp-for="@Model.RolesList[i].RoleName" hidden/>
                            <input asp-for="@Model.RolesList[i].IsSelected" class="form-check-input" />
                            <label class="form-check-label" asp-for="@Model.RolesList[i].IsSelected">
                                @Model.RolesList[i].RoleName
                            </label>
                        </div>
                    }
                </div>
                
                <div class="form-group pt-3 row">
                    <div class="col-md-6">
                        <a class="btn btn-secondary w-100" asp-action="Index">Back to List</a>
                    </div>
                    <div class="col-md-6">
                       
                            <input class="btn btn-success w-100 form-control" type="submit" value="Update"/>
                        
                    </div>
                </div>
            </div>
    </div>

</div>

</form>

```
### Lock Unlock Users 
- For locking/unlocking users we have the following code:
  ```c#
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> LockUnlock(string userId)
    {
    ApplicationUser user = _db.ApplicationUser.FirstOrDefault(x => x.Id == userId);
    if (user == null)
    {
        return NotFound();
    }

    if(user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
    {
        //user is locked and will remain locked until locked out endtime
        //clicking on this action will unlock them
        user.LockoutEnd = DateTime.Now;
        TempData[SD.Success] = "User unlocked successfully";

    } else
    {
        //user is not locked and we want to lock the user
        user.LockoutEnd = DateTime.Now.AddYears(1000);
        TempData[SD.Success] = "User locked successfully";
    }

    _db.SaveChanges();

    return RedirectToAction(nameof(Index));
    }

  ```
  - For deleting users, we have the following code:
```c#
  [HttpPost]
 [ValidateAntiForgeryToken]
 public async Task<IActionResult> DeleteUser(string userId)
 {
     var user = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
     if(user == null)
     {
         return NotFound();
     }
     _db.ApplicationUser.Remove(user);
     _db.SaveChanges();
     TempData["Success"] = "User deleted successfully";
     return RedirectToAction(nameof(Index));
 }

```

## Claim Management
- We should use combination of Roles and Claims 
- If role is Admin, we can add further claims for the Admin users 
- Claims is built in AspNetCore Identity
- *We have AspNetUserClaims ans AspNetRoleClaims table*
- There we have Claim Type and Claim Value
- We have to create a Claims Store where we will have all the claims in the application
- We can create the Crud Functionality around Claims same as Roles
```c#
[HttpGet]
public async Task<IActionResult> ManageUserClaim(string userId)
{
    ApplicationUser user = await _userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return NotFound();
    }
    var existingUserClaims = await _userManager.GetClaimsAsync(user);
    var model = new ClaimsViewModel()
    {
        User = user
    };
    foreach (Claim claim in ClaimStore.claimsList)
    {
        ClaimSelection userClaim = new()
        {
            ClaimType = claim.Type
        };
        if (existingUserClaims.Any(c => c.Type == claim.Type))
        {
            userClaim.IsSelected = true;
        }
        model.ClaimsList.Add(userClaim);
    }
    return View(model);
}



[HttpPost]
public async Task<IActionResult> ManageUserClaim(ClaimsViewModel claimsViewModel)
{
    ApplicationUser user = await _userManager.FindByIdAsync(claimsViewModel.User.Id);
    if (user == null)
    {
        return NotFound();
    }
    var oldUserClaims = await _userManager.GetClaimsAsync(user);
    //Remove old roles
    var result = await _userManager.RemoveClaimsAsync(user, oldUserClaims);

    if (!result.Succeeded)
    {
        TempData[SD.Error] = "Error while removing claims";
        return View(claimsViewModel);
    }

    result = await _userManager.AddClaimsAsync(user,
        claimsViewModel.ClaimsList.Where(x => x.IsSelected).Select(x => new Claim(x.ClaimType,x.IsSelected.ToString())));


    if (!result.Succeeded)
    {
        TempData[SD.Error] = "Error while adding claims";
        return View(claimsViewModel);
    }

    TempData[SD.Success] = "Claims assigned Successfully";
    return RedirectToAction(nameof(Index));
}

```
- The View Model for Claims is as follows:
```c#
namespace IdentityManager.Models.ViewModels
{
    public class ClaimsViewModel
    {
        public ClaimsViewModel()
        {
            ClaimsList = [];
        }
        public List<ClaimSelection> ClaimsList { get; set; }
        public ApplicationUser User { get; set; }

    }

    public class ClaimSelection
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }
}

```
- Claim Store currently looks like this:
```c#
  public static class ClaimStore
 {
     public static List<Claim> claimsList = [
         new Claim("Create","Create"),
         new Claim("Edit","Edit"),
         new Claim("Delete","Delete")

         ];

 }
```
- ![alt text](image-8.png)
- ![alt text](image-9.png)

## Role Policy and Requirements in .NET
- Policy based authorized is designed to decouple authorization and application logic
- A policy is just a collection of requirements which the user must meet before access is granted
- Policy depends on business logic
- We can have a policy which is just a condition that only authorized admin user can access this particular endpoint
- Creating a Policy is done in Program.cs
  ```c#
    builder.Services.AddAuthorization(opt =>
    {
    opt.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    opt.AddPolicy("AdminANDUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    });
  ```
- Working with Claims is not possible in Roles Based Authorization. Need Claims based authorization
- Setup AccessCheckerController with corresponding Views
```c#
    using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        //Anyone can access this

        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }


        //Anyone that has logged in can access
        public IActionResult AuthorizedAccess()
        {
            return View();
        }
        //Anyone that has logged in with user or admin role can access

        [Authorize(Roles = $"{SD.Admin},{SD.User}")]
        public IActionResult UserOrAdminRoleAccess()
        {
            return View();
        }

        //[Authorize(Roles = $"{SD.Admin},{SD.User}")]
        [Authorize(Policy = "AdminANDUser")]
        public IActionResult UserANDAdminRoleAccess()
        {
            return View();
        }

        //Anyone that has logged in with Admin Role can access
        //[Authorize(Roles = SD.Admin)]
        [Authorize(Policy ="Admin")]
        public IActionResult AdminRoleAccess()
        {
            return View();
        }

        //Anyone that has logged in with Admin Role and Create Claim can access
        [Authorize(Policy = "Admin_CreateAccess_Claim")]
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        //Anyone that has logged in with Admin Role and Create & Edit & Delete Claim can access and Not OR
        [Authorize(Policy = "Admin_CreateEditDeleteAccess_Claim")]
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }

        //Anyone that has logged in with Admin Role and Create & Edit & Delete Claim can access and Not OR
        [Authorize(Policy = "Admin_CreateEditDeleteAccess_Claim_OR_SuperAdminRole")]
        public IActionResult Admin_Create_Edit_DeleteAccess_OR_SuperAdmin()
        {
            return View();
        }
    }
}

```
- For Claims, we create Claims in Program.cs 
  ```c#
    builder.Services.AddAuthorization(opt =>
    {
    opt.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
    opt.AddPolicy("AdminANDUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
    opt.AddPolicy("Admin_CreateAccess_Claim", policy => policy.RequireRole(SD.Admin).RequireClaim("Create","True"));
    opt.AddPolicy("Admin_CreateEditDeleteAccess_Claim", policy => policy
    .RequireRole(SD.Admin)
    .RequireClaim("Create", "True")
    .RequireClaim("Edit", "True")
    .RequireClaim("Delete", "True"))
    ;
    opt.AddPolicy("Admin_CreateEditDeleteAccess_Claim_OR_SuperAdminRole", policy => policy.RequireAssertion(
        context=>
    Admin_CreateEditDeleteAccess_Claim_OR_SuperAdminRole(context)
    ));


     bool Admin_CreateEditDeleteAccess_Claim_OR_SuperAdminRole(AuthorizationHandlerContext context)
    {
    return (
    context.User.IsInRole(SD.Admin)
    && context.User.HasClaim(c => c.Type == "Create" && c.Value == "True")
    && context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True")
    && context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True")
    )

    ||
    context.User.IsInRole(SD.SuperAdmin);
    }
  ```
  ## Requirements and Handlers in Policy
  - We want to implement a custom policy in which we will display a special page to users whose accounts are over 1000 days old and user role is Admin 
  - ![alt text](image-10.png)
  - We will create a handler as follows:
  - ![alt text](image-11.png)
### Adding Custom Authorization Handler
```c#
     public class OnlySuperAdminChecker : AuthorizationHandler<OnlySuperAdminChecker>, IAuthorizationRequirement
 {
     protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OnlySuperAdminChecker requirement)
     {
         if(context.User.IsInRole(SD.SuperAdmin))
         {
             context.Succeed(requirement);
             return Task.CompletedTask;
         }
         else return Task.CompletedTask;
     }
 }

 //Using Custom Authorization Holder
 //Configuring in Program.cs file first
  opt.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));

  //Adding custom policy to the Action method
  
        [HttpPost]
        [ValidateAntiForgeryToken]
        //[Authorize(Roles = SD.SuperAdmin)]
        [Authorize(Policy = "OnlySuperAdminChecker")]
        public async Task<IActionResult> Delete(string roleId)
        {
        }

```
- Please note that when we create a Policy in Program.cs file, we add a built in Authorization Requirements
- For e.g if we write RequireRole() we use the RoleAuthorizationRequirement and when we use RequireClaim we use the ClaimsAuthorizationRequirement
- Similarly in RequireAssertion we add an Assertion Requirement
- So, as you can see above, when we add a Custom Authorization Requirement, we also have to specify the Authorization Requirement
- In our case, we implement the IAuthorizationRequirement interface

## Implementing Custom Policies based on Requirements
- We can create our own specific Requirements and then create Authorization Handlers to handle those requirements
- For e.g we can have a DateCreated Field for each user and check that if all users that were created more than 1000 days ago can access a specific page
- First we create the Requirement
```c#
 public class AdminWithMoreThan1000DaysRequirement:IAuthorizationRequirement
{
    public AdminWithMoreThan1000DaysRequirement(int days)
    {
        Days = days;
    }
    public int Days { get; set; }
}

```
- Then we create the Handler
```c#
 public class AdminWithOver1000DaysHandler : AuthorizationHandler<AdminWithMoreThan1000DaysRequirement>
{
    private readonly INumberOfDaysForAccount _numberOfDaysForAccount;
    public AdminWithOver1000DaysHandler(INumberOfDaysForAccount numberOfDaysForAccount)
    {
        _numberOfDaysForAccount = numberOfDaysForAccount;
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminWithMoreThan1000DaysRequirement requirement)
    {
        if(!context.User.IsInRole(SD.Admin))
        {
            return Task.CompletedTask;
        }

        //this is an admin account
        var userId = context.User.FindFirst(c=>c.Type == ClaimTypes.NameIdentifier)?.Value;
        var numberOfDays = _numberOfDaysForAccount.Get(userId);
        if (numberOfDays >= requirement.Days)
        {
            context.Succeed(requirement); 
        }
        return Task.CompletedTask;
    }
}

```
- Next we specific a policy in Program.cs 
```c#
     opt.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
```
- Finally we can call this policy over an Action Method 
```c#
   [Authorize(Policy = "AdminWithMoreThan1000Days")]
  public IActionResult OnlyNishant()
  {
      return View();
  }
```
- Similar to this we can also check if a user has a specific text in his FirstName then that user can see a specific Page
- Create the Requirement first
```c#
 public class FirstNameAuthRequirement : IAuthorizationRequirement
{
    public FirstNameAuthRequirement(string name)
    {
        Name = name;
    }
    public string Name { get; set; }
}
```
- Add the claim when the user logs in Login Post Action Method in AccountController.cs
```c#
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

```
- Next create the handler
```c#
 public class FirstNameAuthHandler : AuthorizationHandler<FirstNameAuthRequirement>
{
    public UserManager<ApplicationUser> _userManager { get; set; }
    public ApplicationDbContext _db { get; set; }
    public FirstNameAuthHandler(UserManager<ApplicationUser> userManager, ApplicationDbContext db)
    {
        _userManager = userManager;
        _db = db;
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstNameAuthRequirement requirement)
    {

        var userId = context.User.FindFirst(c=>c.Type == ClaimTypes.NameIdentifier)?.Value;
        var user = _db.ApplicationUser.FirstOrDefault(u=>u.Id == userId);
        if (user != null)
        {
            var firstNameClaim = _userManager.GetClaimsAsync(user)
                .GetAwaiter().GetResult()
                .FirstOrDefault(u => u.Type == "FirstName");

            if (firstNameClaim != null)
            {
                if (firstNameClaim.Value.ToLower().Contains(requirement.Name.ToLower()))
                {
                    context.Succeed(requirement);
                }
            }
        }
        return Task.CompletedTask;
    }
}
```
- Next, create Policy in Program.cs 
```c#
  opt.AddPolicy("FirstNameAuth", policy => policy.Requirements.Add(new FirstNameAuthRequirement("Admin")));
```
- Then add this policy over an Action Method
```c#
 [Authorize(Policy = "FirstNameAuth")]
public IActionResult FirstNameAuth()
{
    return View();
}
```

## Single Sign On
  - Single Sign On can now be done using Microsoft Entra ID 
  - We will first need to do an App Registration
  - ![alt text](image-12.png)
  - Then we need to copy the Client Id 
  - ![alt text](image-13.png)
  - Then we need to create a Client Secret
  - ![alt text](image-14.png)
  - Finally in our app we need to setup microsoft as an external authentication provider
  - We need to install a nuget package: Microsoft.AspNetCore.Authentication.MicrosoftAccount
  - Then we need to configure Program.cs with clientId and client secret
  ```c#
    builder.Services.AddAuthentication().AddMicrosoftAccount(opt =>
    {
    opt.ClientId = "41d9a19b-4b1c-4a96-b99e-4064f002acbd";
    opt.ClientSecret = "iEW8Q~6zvfiNplxiWiZq41Dli04IRm554Q2LEbab";
    });
  ```
- Next step is to add a link to the external identity provider like Microsoft in our case
- We need to modify Login.cshtml to include the below mentioned code
- Please note we iterate through all external authentication schemes configured in our project and get the login providers from them
```c#
    @model LoginViewModel
    @using Microsoft.AspNetCore.Identity
    @inject SignInManager<ApplicationUser> signInManager
        @{
    var schemes = await signInManager.GetExternalAuthenticationSchemesAsync();
    var loginProviders = schemes.ToList();
    }

    @if(loginProviders.Count() > 0)
    {
    <div>
        <hr/>
        <div class="col-12 p-3 text-center border rounded">
            <section>
                <p>Use another service to log in</p>
                <form asp-controller="Account" asp-action="ExternalLogin" asp-route-returnUrl="@ViewBag.ReturnUrl" method="post" role="form">
                    <div>
                        <p>
                            @foreach(var provider in loginProviders)
                            {
                                <button type="submit" class="btn btn-primary" name="provider" value="@provider.Name">@provider.Name</button>
                            }
                        </p>
                    </div>
                </form>
            </section>
            </div>
        </div>
    
    }


```

- Then we will have to setup the HttpPost method for External Login and also setup a callback that the external provider returns to after authentication
```c#
 [HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public IActionResult ExternalLogin(string provider, string returnUrl = null)
{
    var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { returnUrl });
    var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
    return  Challenge(properties,provider);
}

[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
{

    returnUrl = returnUrl ?? Url.Content("~/");
    if(remoteError != null)
    {
        ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
        return View(nameof(Login));
    }

    var info = await _signInManager.GetExternalLoginInfoAsync();
    if(info == null)
    {
        return RedirectToAction(nameof(Login));
    }

    //sign in the user with this external login provider. only if they have a login
    var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
    if(result.Succeeded)
    {
        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
        return LocalRedirect(returnUrl);
    }
    if (result.RequiresTwoFactor)
    {
        return RedirectToAction(nameof(VerifyAuthenticatorCode), new {  returnUrl });
    }
    else
    {
        //that means user account is not created and we will display a view to create an account
        ViewBag.ReturnUrl = returnUrl;
        ViewBag.ProviderDisplayName = info.ProviderDisplayName;
        return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel
        {
            Email = info.Principal.FindFirstValue(ClaimTypes.Email),
            Name = info.Principal.FindFirstValue(ClaimTypes.Name)
            //Email = "",
            //Name = ""
        });
    }
}

```
- This will display an External Login Confirmation page to the user if he is coming for the first time. If the user has already registered, he will be taken to home screen
- Finally if we have a first time user, we will need to register him like this
```c#
 [HttpPost]
[AllowAnonymous]
[ValidateAntiForgeryToken]
public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model
    ,string returnUrl = null)
{

    returnUrl = returnUrl ?? Url.Content("~/");
    if(ModelState.IsValid)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return View("Error");
        }

        var user = new ApplicationUser
        {
            UserName = model.Email,
            Email = model.Email,
            Name = model.Name,
            NormalizedEmail = model.Email.ToUpper(),
            DateCreated = DateTime.Now
        };

        var result = await _userManager.CreateAsync(user);
        if (result.Succeeded)
        {
           
           await _userManager.AddToRoleAsync(user, SD.User);
            //Add External Login Info
            result = await _userManager.AddLoginAsync(user, info);
            if(result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnUrl);
            }

        }

        AddErrors(result);
    }

    ViewBag.ReturnUrl = returnUrl;
    return View(model);
    
}

```
- Similar to Microsoft, we can setup Facebook login also once we add the Facebook Authentication nuget package like this
- We will have AppId and AppSecret in case of facebook
```c#
builder.Services.AddAuthentication().AddFacebook(opt =>
{
    opt.ClientId = "";
    opt.ClientSecret = "";
    
});
```
- We also need to configure our redirectUrl in similar way to microsoft as localhost:7135/signin-facebook


  







  