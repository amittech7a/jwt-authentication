using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;

        public UserController(ILogger<UserController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("GetUserData")]
        [Authorize(Policy = "User")]
        public IActionResult GetUserData()
        {
            return Ok("User data");
        }

        [HttpGet]
        [Route("GetAdminData")]
        [Authorize(Policy = "Admin")]
        public IActionResult GetAdminData()
        {
            return Ok("Admin data");
        }
    }
}
