using Microsoft.AspNetCore.Identity;

namespace FullLoginApp.Server.Models
{
    public class AppUser : IdentityUser
    {
        public string? FullName { get; set; }
    }
}
