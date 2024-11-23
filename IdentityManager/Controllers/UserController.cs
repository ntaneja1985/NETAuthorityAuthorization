using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;

        public UserController(ApplicationDbContext db, UserManager<ApplicationUser> userManager)
        {
            _db = db;
            _userManager = userManager;
        }
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
    }
}
