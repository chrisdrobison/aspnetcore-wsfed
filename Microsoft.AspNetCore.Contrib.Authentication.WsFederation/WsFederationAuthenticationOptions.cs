using System;
using System.IdentityModel.Tokens;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.AspNetCore.Contrib.Authentication.WsFederation
{
    public class WsFederationAuthenticationOptions : RemoteAuthenticationOptions
    {
        private SecurityTokenHandlerCollection _securityTokenHandlers;

        /// <summary>
        /// Initializes a new <see cref="WsFederationAuthenticationOptions"/>
        /// </summary>
        public WsFederationAuthenticationOptions()
            : this(WsFederationAuthenticationDefaults.AuthenticationType)
        {
        }

        /// <summary>
        /// Initializes a new <see cref="WsFederationAuthenticationOptions"/>
        /// </summary>
        /// <param name="authenticationScheme"> corresponds to the IIdentity AuthenticationType property. <see cref="AuthenticationOptions.AuthenticationScheme"/>.</param>
        public WsFederationAuthenticationOptions(string authenticationScheme)
        {
            AutomaticAuthenticate = true;
            AuthenticationScheme = authenticationScheme;
            CallbackPath = new PathString("/signin-wsfed");
            DisplayName = WsFederationAuthenticationDefaults.Caption;
            BackchannelTimeout = TimeSpan.FromMinutes(1);
            UseTokenLifetime = true;
            RefreshOnIssuerKeyNotFound = true;
            Events = new WsFederationEvents();
        }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// when retrieving metadata.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public Func<object, X509Certificate, X509Chain, SslPolicyErrors, bool> BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// Configuration provided directly by the developer. If provided, then MetadataAddress and the Backchannel properties
        /// will not be used. This information should not be updated during request processing.
        /// </summary>
        public WsFederationConfiguration Configuration { get; set; }

        /// <summary>
        /// Gets or sets the address to retrieve the wsFederation metadata
        /// </summary>
        public string MetadataAddress { get; set; }

        /// <summary>
        /// Responsible for retrieving, caching, and refreshing the configuration from metadata.
        /// If not provided, then one will be created using the MetadataAddress and Backchannel properties.
        /// </summary>
        public IConfigurationManager<WsFederationConfiguration> ConfigurationManager { get; set; }

        /// <summary>
        /// Indicates that the authentication session lifetime (e.g. cookies) should match that of the authentication token.
        /// If the token does not provide lifetime information then normal session lifetimes will be used.
        /// This is disabled by default.
        /// </summary>
        public bool UseTokenLifetime { get; set; }

        /// <summary>
        /// Gets or sets if a metadata refresh should be attempted after a SecurityTokenSignatureKeyNotFoundException. This allows for automatic
        /// recovery in the event of a signature key rollover. This is enabled by default.
        /// </summary>
        public bool RefreshOnIssuerKeyNotFound { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IWsFederationEvents"/> to call when processing WsFederation messages.
        /// </summary>
        public new IWsFederationEvents Events { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityTokenHandlerCollection"/> of <see cref="SecurityTokenHandler"/>s used to read and validate <see cref="SecurityToken"/>s.
        /// </summary>
        public SecurityTokenHandlerCollection SecurityTokenHandlers
        {
            get { return _securityTokenHandlers; }
            set
            {
                _securityTokenHandlers = value ?? throw new ArgumentNullException("SecurityTokenHandlers");
            }
        }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the parameters used to validate identity tokens.
        /// </summary>
        /// <remarks>Contains the types and definitions required for validating a token.</remarks>
        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

        /// <summary>
        /// Gets or sets the 'wreply'.
        /// </summary>
        public string Wreply { get; set; }

        /// <summary>
        /// Gets or sets the 'wreply' value used during sign-out.
        /// If none is specified then the value from the Wreply field is used.
        /// </summary>
        public string SignOutWreply { get; set; }

        /// <summary>
        /// Gets or sets the 'wtrealm'.
        /// </summary>
        public string Wtrealm { get; set; }
    }
}