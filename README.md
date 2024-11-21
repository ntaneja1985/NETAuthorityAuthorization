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





  