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

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLogin userLogin)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userLogin.Email);
            
            if (user != null && BCrypt.Net.BCrypt.Verify(userLogin.Password, user.Password))
            {
                var token = Generate(user);
                return Ok(token);
            }
            return Unauthorized();
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegister user)
        {
            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == user.Email);
            
            if (existingUser != null)
            {
                return BadRequest("User already exists");
            }
            
            var newUser = new UserModel
            {
                Email = user.Email,
                Name = user.Name,
                Surname = user.Surname,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password),
            };
            await _context.Users.AddAsync(newUser);
            await _context.SaveChangesAsync();
            
            var token = Generate(newUser);
            return Ok(token);
        }

        private string Generate(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? string.Empty));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim("email", user.Email),
                new Claim("name", user.Name),
                new Claim("surname", user.Surname),
                new Claim("role", user.Role)
            };
            var token = new JwtSecurityToken(_configuration["Jwt:Issuer"], 
                _configuration["Jwt:Audience"], 
                claims, expires: 
                DateTime.Now.AddDays(15), 
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    };
}
