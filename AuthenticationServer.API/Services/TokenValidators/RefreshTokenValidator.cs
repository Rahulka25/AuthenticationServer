using AuthenticationServer.API.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationServer.API.Services.TokenValidators
{
    public class RefreshTokenValidator
    {
        private readonly AuthenticationConfiguration _authenticactionConfiguration;

        public RefreshTokenValidator(AuthenticationConfiguration authenticactionConfiguration)
        {
            _authenticactionConfiguration = authenticactionConfiguration;
        }

        public bool Validate(string refreshToken)
        {
            TokenValidationParameters validationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authenticactionConfiguration.RefreshTokenSecret)),
                ValidIssuer = _authenticactionConfiguration.Issuer,
                ValidAudience = _authenticactionConfiguration.Audience,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            try {
                tokenHandler.ValidateToken(refreshToken, validationParameters, out SecurityToken validatedToken);
                return true;
            } catch (Exception)
            {
                return false;
            }
        }
    }
}
