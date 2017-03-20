using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCoreWsFed.Events
{
    public class SecurityTokenValidatedContext : BaseWsFederationContext
    {
        public SecurityTokenValidatedContext(HttpContext context, WsFederationAuthenticationOptions options)
            : base(context, options)
        {
        }
    }
}