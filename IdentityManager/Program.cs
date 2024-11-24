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
});

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
