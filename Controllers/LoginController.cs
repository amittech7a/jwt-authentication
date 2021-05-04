using JWTAuthentication.DTOs;
using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly ILogger<LoginController> _logger;
        private readonly IConfiguration _configuration;
        public LoginController(IConfiguration configuration, ILogger<LoginController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        [AllowAnonymous]
        [HttpPost("token")]
        [Consumes("application/json")]
        public IActionResult GenerateToken(LoginDto loginDto)
        {
            if (IsAuthenticate(loginDto))
            {
                User user = GetUserById(loginDto.UserName);
                var tokenString = GenerateJWTToken(user);
                var response = Ok(new
                {
                    token = tokenString,
                    userDetails = user,
                });
                return response;
            }
            return Unauthorized();
        }

        private bool IsAuthenticate(LoginDto loginDto)
        {
            if (JWTAuthentication.Models.User.DefaultUsers().Any(x => x.UserName == loginDto.UserName && x.Password == loginDto.Password))
            {
                return true;
            }
            return false;
        }

        private User GetUserById(string userId)
        {
            var user = JWTAuthentication.Models.User.DefaultUsers().Where(x => x.UserName == userId).FirstOrDefault();
            return user;
        }

        private string GenerateJWTToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["jWT:SecretKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim("role", user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}
