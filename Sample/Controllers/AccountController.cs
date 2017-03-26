using System.Linq;
using AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Sample.Controllers
{
    public class AccountController : Controller
    {
        // GET: /<controller>/
        public IActionResult Login(string source = "/")
        {
            if (User.Identities.Any(identity => identity.IsAuthenticated))
            {
                return Redirect(source);
            }

            return Challenge(new AuthenticationProperties { RedirectUri = source },
                WsFederationAuthenticationDefaults.AuthenticationType);
        }

        public IActionResult Logout()
        {
            return SignOut(new AuthenticationProperties { RedirectUri = "http://localhost:8550/" },
                CookieAuthenticationDefaults.AuthenticationScheme,
                WsFederationAuthenticationDefaults.AuthenticationType);
        }
    }
}