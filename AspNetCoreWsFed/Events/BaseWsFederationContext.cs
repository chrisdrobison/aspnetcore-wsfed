using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCoreWsFed
{
    public class BaseWsFederationContext : BaseControlContext
    {
        public BaseWsFederationContext(HttpContext context, WsFederationAuthenticationOptions options) : base(context)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public WsFederationAuthenticationOptions Options { get; }

        public WsFederationMessage ProtocolMessage { get; set; }
    }
}