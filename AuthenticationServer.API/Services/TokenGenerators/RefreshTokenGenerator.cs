using AuthenticationServer.API.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthenticationServer.API.Services.TokenGenerators
{
    public class RefreshTokenGenerator
    {
        private readonly AuthenticationConfiguration _authenticationConfiguration;
        private readonly TokenGenerator _tokenGenerator;

        public RefreshTokenGenerator(AuthenticationConfiguration authenticationConfiguration, TokenGenerator tokenGenerator = null)
        {
            _authenticationConfiguration = authenticationConfiguration; 
            this._tokenGenerator = tokenGenerator;
        }

        public string GenerateToken()
        {
            return _tokenGenerator.GenerateToken(_authenticationConfiguration.RefreshTokenSecret,
                _authenticationConfiguration.Issuer,
                _authenticationConfiguration.Audience,
                _authenticationConfiguration.RefreshTokenExpirationMinutes,
                null);
        }
    }
}
