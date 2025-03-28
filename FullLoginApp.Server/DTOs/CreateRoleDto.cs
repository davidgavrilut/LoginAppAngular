using System.ComponentModel.DataAnnotations;

namespace FullLoginApp.Server.DTOs
{
    public class CreateRoleDto
    {
        [Required(ErrorMessage = "Role name is required!")]
        public string RoleName { get; set; } = null!;
    }
}