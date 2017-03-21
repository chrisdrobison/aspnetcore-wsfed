using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace AspNetCore.Authentication.WsFederation
{
    public class RedirectContext : BaseWsFederationContext
    {
        public RedirectContext(HttpContext context, WsFederationAuthenticationOptions options) : base(context, options)
        {
        }

        public AuthenticationProperties Properties { get; set; }
    }
}