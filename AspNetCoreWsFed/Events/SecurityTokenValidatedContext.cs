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

        /// <summary>
        ///     Gets or set the <see cref="AuthenticationTicket" />
        /// </summary>
        public AuthenticationTicket AuthenticationTicket { get; set; }
    }
}