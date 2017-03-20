using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Contrib.Authentication.WsFederation.Events
{
    public class SecurityTokenValidatedContext : BaseWsFederationContext
    {
        public SecurityTokenValidatedContext(HttpContext context, WsFederationAuthenticationOptions options)
            : base(context, options)
        {
        }
    }
}