using AuthenticationServer.API.Models;
using AuthenticationServer.API.Models.Responses;
using AuthenticationServer.API.Services.RefreshTokenRepositories;
using AuthenticationServer.API.Services.TokenGenerators;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationServer.API.Services.Authenticators
{
    public class Authenticator
    {
        private readonly AccessTokenGenerator _accesTokenGenerator;
        private readonly RefreshTokenGenerator _refreshTokenGenerator;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public Authenticator(IRefreshTokenRepository refreshTokenRepository, RefreshTokenGenerator refreshTokenGenerator, AccessTokenGenerator accesTokenGenerator)
        {
            _refreshTokenRepository = refreshTokenRepository;
            _refreshTokenGenerator = refreshTokenGenerator;
            _accesTokenGenerator = accesTokenGenerator;
        }

        public async Task<AuthenticatedUserResponse> Authenticate(User user)
        {

            var accessToken = _accesTokenGenerator.GenerateToken(user);
            var refreshToken = _refreshTokenGenerator.GenerateToken();

            RefreshToken refreshTokenDTO = new RefreshToken()
            {
                Token = refreshToken,
                UserId = user.Id
            };

            await _refreshTokenRepository.Create(refreshTokenDTO);

            return new AuthenticatedUserResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }
    }
}
