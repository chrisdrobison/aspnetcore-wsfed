using System;
using System.IdentityModel.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCoreWsFed
{
    public class WsFederationAuthenticationOptions : RemoteAuthenticationOptions
    {
        private SecurityTokenHandlerCollection _securityTokenHandlers;
        private TokenValidationParameters _tokenValidationParameters;

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
            AuthenticationScheme = authenticationScheme;
            DisplayName = WsFederationAuthenticationDefaults.Caption;
            _tokenValidationParameters = new TokenValidationParameters();
            BackchannelTimeout = TimeSpan.FromMinutes(1);
            UseTokenLifetime = true;
            RefreshOnIssuerKeyNotFound = true;
        }

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
    }
}