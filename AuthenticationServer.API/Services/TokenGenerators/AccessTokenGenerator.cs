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
        private readonly TokenGenerator _tokenGenerator;

        public AccessTokenGenerator(AuthenticationConfiguration authenticationConfiguration, TokenGenerator tokenGenerator = null)
        {
            _authenticationConfiguration = authenticationConfiguration;
            this._tokenGenerator = tokenGenerator;
        }

        public string GenerateToken(User user) {
            List<Claim> claims = new List<Claim>()
            {
                new Claim("id", user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
            };

            return _tokenGenerator.GenerateToken(_authenticationConfiguration.AccessTokenSecret,
                _authenticationConfiguration.Issuer,
                _authenticationConfiguration.Audience,
                _authenticationConfiguration.AccessTokenExpirationMinutes,
                claims);
        }
    }
}
