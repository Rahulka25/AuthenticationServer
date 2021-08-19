using AuthenticationServer.API.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationServer.API.Services.TokenGenerators
{
    public class AccessTokenGenerator
    {
        private readonly AuthenticationConfiguration _authenticationConfiguration;

        public AccessTokenGenerator(AuthenticationConfiguration authenticationConfiguration)
        {
            _authenticationConfiguration = authenticationConfiguration;
        }

        public string GenerateToken(User user) {
            SecurityKey securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authenticationConfiguration.AccessTokenSecret));
            SigningCredentials signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            List<Claim> claims = new List<Claim>()
            {
                new Claim("id", user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
            };
            JwtSecurityToken token = new JwtSecurityToken(_authenticationConfiguration.Issuer,
                _authenticationConfiguration.Audience,
                claims,
                DateTime.UtcNow,
                DateTime.UtcNow.AddMinutes(_authenticationConfiguration.AccessTokenExpirationMinutes),
                signingCredentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
