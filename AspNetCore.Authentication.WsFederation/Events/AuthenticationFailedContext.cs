using System;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authentication.WsFederation
{
    public class AuthenticationFailedContext : BaseWsFederationContext
    {
        public AuthenticationFailedContext(HttpContext context, WsFederationAuthenticationOptions options)
            : base(context, options)
        {
        }

        public Exception Exception { get; set; }
    }
}