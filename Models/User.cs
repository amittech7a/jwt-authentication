using System.Collections.Generic;

namespace JWTAuthentication.Models
{
    public class User
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }

        public static IList<User> DefaultUsers()
        {
            var user1 = new User { UserName = "admin", Password = "admin", Role = "Admin" };
            var user2 = new User { UserName = "user", Password = "user", Role = "User" };
            return new List<User> { user1, user2 };
        }
    }
}
