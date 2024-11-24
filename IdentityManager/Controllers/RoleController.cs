using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
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
        //[Authorize(Roles = SD.SuperAdmin)]
        [Authorize(Policy = "OnlySuperAdminChecker")]
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
}
