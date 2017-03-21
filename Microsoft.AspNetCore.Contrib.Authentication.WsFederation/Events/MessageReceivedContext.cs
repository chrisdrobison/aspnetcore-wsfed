using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authentication.WsFederation.Events
{
    public class MessageReceivedContext : BaseWsFederationContext
    {
        public MessageReceivedContext(HttpContext context, WsFederationAuthenticationOptions options)
            : base(context, options)
        {
        }
    }
}