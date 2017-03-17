using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;

namespace AspNetCoreWsFed.Events
{
    public class MessageReceivedContext : BaseWsFederationContext
    {
        public MessageReceivedContext(HttpContext context, WsFederationAuthenticationOptions options)
            : base(context, options)
        {
        }

        public AuthenticationProperties Properties { get; set; }
    }
}