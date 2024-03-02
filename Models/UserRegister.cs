using System.ComponentModel.DataAnnotations;

namespace Auth.Models
{
    public class UserRegister
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        public string Surname { get; set; }
        public string Name { get; set; }
    }
}
