using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityManager.Authorize
{
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
}
