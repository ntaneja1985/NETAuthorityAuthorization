namespace IdentityManager.Models.ViewModels
{
    public class ClaimsViewModel
    {
        public ClaimsViewModel()
        {
            ClaimsList = [];
        }
        public List<ClaimSelection> ClaimsList { get; set; }
        public ApplicationUser User { get; set; }

    }

    public class ClaimSelection
    {
        public string ClaimType { get; set; }
        public bool IsSelected { get; set; }
    }
}
