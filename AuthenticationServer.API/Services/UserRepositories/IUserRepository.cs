using AuthenticationServer.API.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationServer.API.Services.UserRepositories
{
    public interface IUserRepository

    {
        Task<User> GetByEmail(string email);
        Task<User> GetByUserName(string userName);

        Task<User> Create(User user);
        Task<User> GetById(Guid userId);
    }
}
