using System.Security.Claims;
using Auth.Data;
using Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly AppDbContext _context;

        public UserController(IConfiguration configuration, AppDbContext context)
        {
            _configuration = configuration;
            _context = context;
        }
        
        public record EmailBody(string Email);
        
        [HttpPut("email")]
        [Authorize]
        public async Task<IActionResult> Email([FromBody] EmailBody body)
        {
            var user = GetCurrentUser();
            if (user is null) return Unauthorized();
            
            var userToUpdate = await _context.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            if (userToUpdate is null) return NotFound();
            
            userToUpdate.Email = body.Email;
            var res = await _context.SaveChangesAsync();
            
            return res > 0 ? Ok("Updated") : Problem();
        }
        
        public record PasswordBody(string OldPassword, string NewPassword);

        [HttpPut("password")]
        [Authorize]
        public async Task<IActionResult> Password([FromBody] PasswordBody body)
        {
            var user = GetCurrentUser();
            if (user is null) return Unauthorized();
            
            var userToUpdate = await _context.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            if (userToUpdate is null) return NotFound();
            
            if (!BCrypt.Net.BCrypt.Verify(body.OldPassword, userToUpdate.Password)) return BadRequest("Wrong password");
            
            userToUpdate.Password = BCrypt.Net.BCrypt.HashPassword(body.NewPassword);
            var res = await _context.SaveChangesAsync();
            
            return res > 0 ? Ok("Updated") : Problem();
        }
        
        [HttpDelete]
        [Authorize]
        public async Task<IActionResult> Delete()
        {
            var user = GetCurrentUser();
            if (user is null) return Unauthorized();
            
            var userToDelete = await _context.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            if (userToDelete is null) return NotFound();
            
            _context.Users.Remove(userToDelete);
            var res = await _context.SaveChangesAsync();
            
            return res > 0 ? Ok("Deleted") : Problem();
        }
        
        [HttpGet("me")]
        [Authorize]
        public IActionResult Get()
        {
            var user = GetCurrentUser();
            if (user is null) return Unauthorized();
            
            var userToGet = _context.Users.FirstOrDefault(u => u.Email == user.Email);
            if (userToGet is null) return NotFound();
            
            return Ok(user);
        }

        private UserModel GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity is null) return null;
            
            var userClaims = identity.Claims;
            return new UserModel
            {
                Email = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Email)?.Value,
                Role = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value
            };
        }
    }
}
