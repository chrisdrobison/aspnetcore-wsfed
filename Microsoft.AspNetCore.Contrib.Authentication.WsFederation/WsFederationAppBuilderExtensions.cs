using System;
using AspNetCore.Authentication.WsFederation;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Builder
{
    public static class WsFederationAppBuilderExtensions
    {
        public static IApplicationBuilder UseWsFederationAuthentication(this IApplicationBuilder app, string wtrealm,
            string metadataAddress)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            if (string.IsNullOrEmpty(wtrealm))
            {
                throw new ArgumentNullException(nameof(wtrealm));
            }
            if (string.IsNullOrEmpty(metadataAddress))
            {
                throw new ArgumentNullException(nameof(metadataAddress));
            }

            return
                app.UseMiddleware<WsFederationAuthenticationMiddleware>(
                    Options.Create(new WsFederationAuthenticationOptions
                    {
                        Wtrealm = wtrealm,
                        MetadataAddress = metadataAddress
                    }));
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

            if (string.IsNullOrWhiteSpace(options.TokenValidationParameters.ValidAudience))
            {
                options.TokenValidationParameters.ValidAudience = options.Wtrealm;
            }

            return app.UseMiddleware<WsFederationAuthenticationMiddleware>(Options.Create(options));
        }
    }
}