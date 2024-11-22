using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models.ViewModels
{
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

        public IEnumerable<SelectListItem>? RoleList { get; set; }

        [Display(Name = "Select Role")]
        public string RoleSelected { get; set; }    

    }
}
