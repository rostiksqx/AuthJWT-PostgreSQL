namespace Auth.Models
{
    public class UserModel : UserRegister
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Role { get; set; } = "user";
    }
}
