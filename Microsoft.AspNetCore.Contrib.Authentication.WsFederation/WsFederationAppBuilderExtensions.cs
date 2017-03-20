using System;
using Microsoft.AspNetCore.Contrib.Authentication.WsFederation;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Builder
{
    public static class WsFederationAppBuilderExtensions
    {
        public static IApplicationBuilder UseWsFederationAuthentication(this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseMiddleware<WsFederationAuthenticationMiddleware>();
        }

        public static IApplicationBuilder UseWsFederationAuthentication(this IApplicationBuilder app,
            WsFederationAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<WsFederationAuthenticationMiddleware>(Options.Create(options));
        }
    }
}