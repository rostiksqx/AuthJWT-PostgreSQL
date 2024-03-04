using System.ComponentModel.DataAnnotations;

namespace Auth.Models
{
    public class UserModel
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        
        public string Role { get; set; } = "user";
        
        public string Email { get; set; }
        
        public string Password { get; set; }
    }
}
