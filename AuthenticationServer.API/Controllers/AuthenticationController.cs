using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthenticationServer.API.Models;
using AuthenticationServer.API.Models.Requests;
using AuthenticationServer.API.Models.Responses;
using AuthenticationServer.API.Services.Authenticators;
using AuthenticationServer.API.Services.RefreshTokenRepositories;
using AuthenticationServer.API.Services.TokenGenerators;
using AuthenticationServer.API.Services.TokenValidators;
using AuthenticationServer.API.Services.UserRepositories;
using Microsoft.AspNetCore.Authorization;
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
        private readonly RefreshTokenValidator _refreshTokenValidator;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly Authenticator _authenticator;

        public AuthenticationController(IUserRepository userRepository, RefreshTokenValidator refreshTokenValidator, IRefreshTokenRepository refreshTokenRepository, Authenticator authenticator)
        {
            this._userRepository = userRepository;
            _refreshTokenValidator = refreshTokenValidator;
            _refreshTokenRepository = refreshTokenRepository;
            _authenticator = authenticator;
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

            AuthenticatedUserResponse tokenResponse = await _authenticator.Authenticate(user);
            return Ok(tokenResponse);
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequestModelState();
            }

            bool isValidRefreshToken = _refreshTokenValidator.Validate(request.RefreshToken);

            if (!isValidRefreshToken)
            {
                return BadRequest(new ErrorResponse("Invalid refresh Token"));
            }

            RefreshToken refreshTokenDTO = await _refreshTokenRepository.GetByToken(request.RefreshToken);
            if(refreshTokenDTO == null)
            {
                return NotFound(new ErrorResponse("Invalid refresh Token"));
            }

            await _refreshTokenRepository.Delete(refreshTokenDTO.Id);

            User user = await _userRepository.GetById(refreshTokenDTO.UserId);
            if (user == null)
            {
                return NotFound(new ErrorResponse("User not found "));
            }

            AuthenticatedUserResponse tokenResponse = await _authenticator.Authenticate(user);
            return Ok(tokenResponse);
        }

        [Authorize]
        [HttpDelete("logout")]
        public async Task<IActionResult> Logout()
        {
            string rawUserId = HttpContext.User.FindFirst("id").Value;
            if(!Guid.TryParse(rawUserId, out Guid userId)) {
                return Unauthorized();
            }

            await _refreshTokenRepository.DeleteAll(userId);
            return NoContent();
        }
        private IActionResult BadRequestModelState()
        {
            var errorMessages = ModelState.Values.SelectMany(item => item.Errors.Select(error => error.ErrorMessage));
            return BadRequest(errorMessages);
        }
    }
}
