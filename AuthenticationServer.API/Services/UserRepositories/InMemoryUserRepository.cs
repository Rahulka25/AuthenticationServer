using AuthenticationServer.API.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationServer.API.Services.UserRepositories
{
    public class InMemoryUserRepository : IUserRepository
    {
        private readonly List<User> _users = new List<User>();
        public Task<User> Create(User user)
        {
            user.Id = Guid.NewGuid();
            _users.Add(user);
            return Task.FromResult(user);
        }

        public Task<User> GetByEmail(string email)
        {
            return Task.FromResult(_users.FirstOrDefault(User => User.Email == email));
        }

        public Task<User> GetByUserName(string userName)
        {
            return Task.FromResult(_users.FirstOrDefault(User => User.UserName == userName));
        }


        Task<User> IUserRepository.GetById(Guid userId)
        {
            return Task.FromResult(_users.FirstOrDefault(User => User.Id == userId));
        }
    }
}
