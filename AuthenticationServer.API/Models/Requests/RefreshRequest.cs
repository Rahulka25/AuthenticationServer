using System.ComponentModel.DataAnnotations;

namespace AuthenticationServer.API.Models.Requests
{
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}