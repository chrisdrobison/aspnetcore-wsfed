using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Security;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.AspNetCore.Contrib.Authentication.WsFederation
{
    public class WsFederationAuthenticationMiddleware : AuthenticationMiddleware<WsFederationAuthenticationOptions>
    {
        public WsFederationAuthenticationMiddleware(RequestDelegate next,
            IOptions<WsFederationAuthenticationOptions> options,
            IOptions<SharedAuthenticationOptions> sharedOptions,
            ILoggerFactory loggerFactory,
            IDataProtectionProvider dataProtectionProvider,
            UrlEncoder encoder)
            : base(next, options, loggerFactory, encoder)
        {
            if (string.IsNullOrEmpty(Options.SignInScheme))
            {
                Options.SignInScheme = sharedOptions.Value.SignInScheme;
            }
            if (string.IsNullOrEmpty(Options.SignInScheme))
            {
                throw new ArgumentException("Options.SignInScheme is required.");
            }

            if (string.IsNullOrWhiteSpace(Options.TokenValidationParameters.AuthenticationType))
            {
                Options.TokenValidationParameters.AuthenticationType = Options.SignInScheme;
            }

            if (Options.StateDataFormat == null)
            {
                var dataProtector = dataProtectionProvider.CreateProtector(
                    typeof(WsFederationAuthenticationMiddleware).FullName,
                    typeof(string).FullName,
                    Options.AuthenticationScheme,
                    "v1"
                );
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (Options.SecurityTokenHandlers == null)
            {
                Options.SecurityTokenHandlers = SecurityTokenHandlerCollectionExtensions.GetDefaultHandlers();
            }

            if (Options.Events == null)
            {
                Options.Events = new WsFederationEvents();
            }

            Uri wreply;
            if (!Options.CallbackPath.HasValue && !string.IsNullOrEmpty(Options.Wreply) &&
                Uri.TryCreate(Options.Wreply, UriKind.Absolute, out wreply))
            {
                Options.CallbackPath = PathString.FromUriComponent(wreply);
            }

            if (Options.ConfigurationManager == null)
            {
                if (Options.Configuration != null)
                {
                    Options.ConfigurationManager =
                        new StaticConfigurationManager<WsFederationConfiguration>(Options.Configuration);
                }
                else
                {
                    var httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
                    {
                        Timeout = Options.BackchannelTimeout,
                        MaxResponseContentBufferSize = 1024 * 1024 * 10
                    };
                    // 10 MB
                    Options.ConfigurationManager =
                        new ConfigurationManager<WsFederationConfiguration>(Options.MetadataAddress, httpClient);
                }
            }
        }

        protected override AuthenticationHandler<WsFederationAuthenticationOptions> CreateHandler()
        {
            return new WsFederationAuthenticationHandler(Logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(WsFederationAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException(
                        "An BackchannelCertificateValidator cannot be specified at the same " +
                        "time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback =
                    new RemoteCertificateValidationCallback(options.BackchannelCertificateValidator);
            }

            return handler;
        }
    }
}