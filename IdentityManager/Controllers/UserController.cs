using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(ApplicationDbContext db, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
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

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            ApplicationUser user = _db.ApplicationUser.FirstOrDefault(x => x.Id == userId);
            if (user == null)
            {
                return NotFound();
            }

            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                //user is locked and will remain locked until locked out endtime
                //clicking on this action will unlock them
                user.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "User unlocked successfully";

            }
            else
            {
                //user is not locked and we want to lock the user
                user.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "User locked successfully";
            }

            _db.SaveChanges();

            return RedirectToAction(nameof(Index));
        }

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
    }
}
