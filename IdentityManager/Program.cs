using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.UI.Services;
using IdentityManager;
using System.Drawing.Text;
using Microsoft.AspNetCore.Authorization;
using IdentityManager.Authorize;
using IdentityManager.Services.IServices;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(
    options => options.UseSqlServer(builder
    .Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender, EmailSender>();

builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.AccessDeniedPath = new PathString("/Account/NoAccess");
});

builder.Services.Configure<IdentityOptions>(
    opt => {
        opt.Password.RequireDigit = false;
        opt.Password.RequireLowercase = false;
        opt.Password.RequireNonAlphanumeric = false;
        opt.Lockout.MaxFailedAccessAttempts = 3;
        opt.SignIn.RequireConfirmedEmail = false;
        opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    });

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
    opt.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
    opt.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));
    opt.AddPolicy("FirstNameAuth", policy => policy.Requirements.Add(new FirstNameAuthRequirement("Admin")));
});

//value: iEW8Q~6zvfiNplxiWiZq41Dli04IRm554Q2LEbab
//ID: 41d9a19b-4b1c-4a96-b99e-4064f002acbd
builder.Services.AddAuthentication().AddMicrosoftAccount(opt =>
{
    //opt.ClientId = "41d9a19b-4b1c-4a96-b99e-4064f002acbd";
    //opt.Client_Secr8_Name = "iEW8Q~6zvfiNplxiWiZq41Dli04IRm554Q2LEbab";
});

//builder.Services.AddAuthentication().AddFacebook(opt =>
//{
//    opt.ClientId = "";
//    opt.Client_Secr8_Name = "";

//});

builder.Services.AddScoped<INumberOfDaysForAccount,NumberOfDaysForAccount>();
builder.Services.AddScoped<IAuthorizationHandler,AdminWithOver1000DaysHandler>();
builder.Services.AddScoped<IAuthorizationHandler, FirstNameAuthHandler>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

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
