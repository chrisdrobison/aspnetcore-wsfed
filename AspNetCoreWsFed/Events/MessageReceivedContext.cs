using Microsoft.AspNetCore.Http;

namespace AspNetCoreWsFed.Events
{
    public class MessageReceivedContext : BaseWsFederationContext
    {
        public MessageReceivedContext(HttpContext context, WsFederationAuthenticationOptions options)
            : base(context, options)
        {
        }
    }
}