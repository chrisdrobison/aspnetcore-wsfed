using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace AspNetCoreWsFed
{
    public class RedirectContext : BaseWsFederationContext
    {
        public RedirectContext(HttpContext context, WsFederationAuthenticationOptions options) : base(context, options)
        {
        }

        public AuthenticationProperties Properties { get; set; }
    }
}