using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthenticationServer.API.Models;
using AuthenticationServer.API.Models.Requests;
using AuthenticationServer.API.Models.Responses;
using AuthenticationServer.API.Services.TokenGenerators;
using AuthenticationServer.API.Services.UserRepositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthenticationServer.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        private readonly AccessTokenGenerator _accesTokenGenerator;

        public AuthenticationController(IUserRepository userRepository, AccessTokenGenerator accessTokenGenerator)
        {
            this._userRepository = userRepository;
            _accesTokenGenerator = accessTokenGenerator;
        }
        // GET: api/<AuthenticationController>
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/<AuthenticationController>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<AuthenticationController>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequestModelState();
            }

            if (request.Password != request.ConfirmPassword)
                return BadRequest( new ErrorResponse("Passwords doesnot match"));

            User existingUserByEmail = await this._userRepository.GetByEmail(request.Email);
            if (existingUserByEmail != null)
                return Conflict(new ErrorResponse("Email already exist"));

            User existingUserByUserName = await this._userRepository.GetByUserName(request.UserName);
            if (existingUserByUserName != null)
                return Conflict(new ErrorResponse("User name already exist"));
            var hasher = new PasswordHasher<User>();
            User registeredUser = new User
            {
                Email = request.Email,
                UserName = request.UserName,
            };
            registeredUser.Password = hasher.HashPassword(registeredUser, request.Password);

            await _userRepository.Create(registeredUser);
            return Ok();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequestModelState();
            }

            User user = await this._userRepository.GetByUserName(request.UserName);
            if (user == null)
            {
                return Unauthorized();
            }
            var hasher = new PasswordHasher<User>();
            var passCompareResult = hasher.VerifyHashedPassword(user, user.Password, request.Password);
            if (passCompareResult == PasswordVerificationResult.Failed)
            {
                return Unauthorized();
            }
            var accessToken = _accesTokenGenerator.GenerateToken(user);
            AuthenticatedUserResponse tokenResponse = new AuthenticatedUserResponse
            {
                token = accessToken
              };
            return Ok(tokenResponse);
        }

        // PUT api/<AuthenticationController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<AuthenticationController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }

        private IActionResult BadRequestModelState()
        {
            var errorMessages = ModelState.Values.SelectMany(item => item.Errors.Select(error => error.ErrorMessage));
            return BadRequest(errorMessages);
        }
    }
}
