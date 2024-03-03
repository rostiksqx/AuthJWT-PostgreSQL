using Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Auth.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration, AppDbContext context)
        {
            _configuration = configuration;
            _context = context;
        }

        public record LoginModel(string Email, string Password);
        
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel userLogin)
        {
            if (!IsValidEmail(userLogin.Email)) return BadRequest("Invalid email");
            
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userLogin.Email);
            
            if (user != null && BCrypt.Net.BCrypt.Verify(userLogin.Password, user.Password))
            {
                var token = Generate(user);
                return Ok(new { Token = token, user.Email });
            }
            return BadRequest();
        }

        public record RegisterModel(string Email, string Password, string ConfirmPassword);

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel user)
        {
            if (!IsValidEmail(user.Email)) return BadRequest("Invalid email");
            
            if (user.Password != user.ConfirmPassword) return BadRequest("Passwords do not match");
            
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            
            if (existingUser != null) return Conflict("User already exists");
            
            var newUser = new UserModel
            {
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password),
            };
            
            await _context.Users.AddAsync(newUser);
            await _context.SaveChangesAsync();
            
            var token = Generate(newUser);
            return Ok(new { Token = token, newUser.Email });
        }

        [HttpGet("check")]
        [Authorize]
        public IActionResult Get()
        {
            return Ok("Hello");
        }

        private string Generate(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? string.Empty));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim("email", user.Email),
                new Claim("role", user.Role)
            };
            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], 
                _configuration["Jwt:Audience"], 
                claims, expires: 
                DateTime.Now.AddDays(15), 
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        
        private bool IsValidEmail(string userEmail)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(userEmail);
                return addr.Address == userEmail;
            }
            catch
            {
                return false;
            }
        }
    };
}
