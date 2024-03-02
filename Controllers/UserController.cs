using System.Security.Claims;
using Auth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [HttpGet("admins")]
        public IActionResult AdminsEndpoint()
        {
            var user = GetCurrentUser();
            // return Ok($"Hello {user.Name} {user.Surname} you are an {user.Role}");
            return Ok(user);
        }
        
        [HttpGet("Me")]
        public IActionResult Get()
        {
            return Ok("You are ");
        }

        private UserModel GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var userClaims = identity.Claims;
                var enumerable = userClaims as Claim[] ?? userClaims.ToArray();
                return new UserModel
                {
                    Email = enumerable.FirstOrDefault(o => o.Type == "Email")?.Value,
                    Name = enumerable.FirstOrDefault(o => o.Type == "name")?.Value,
                    Surname = enumerable.FirstOrDefault(o => o.Type == "surname")?.Value,
                    Role = enumerable.FirstOrDefault(o => o.Type == "role")?.Value
                };
            }
            return null;
        }
    }
}
