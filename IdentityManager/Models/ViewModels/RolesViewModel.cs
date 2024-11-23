namespace IdentityManager.Models.ViewModels
{
    public class RolesViewModel
    {
        public RolesViewModel()
        {
            RolesList = [];
        }
        public List<RoleSelection> RolesList { get; set; }
        public ApplicationUser User { get; set; }

    }

    public class RoleSelection
    {
        public string RoleName { get; set; }
        public bool IsSelected { get; set; }
    }
}
