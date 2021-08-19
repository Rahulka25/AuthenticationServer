﻿using AuthenticationServer.API.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationServer.API.Services.RefreshTokenRepositories
{
    public interface IRefreshTokenRepository
    {
        Task<RefreshToken> GetByToken(string refeshToken);
        Task Create(RefreshToken refreshToken);
        Task Delete(Guid id);

        Task DeleteAll(Guid userId);
    }
}
