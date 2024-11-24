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
