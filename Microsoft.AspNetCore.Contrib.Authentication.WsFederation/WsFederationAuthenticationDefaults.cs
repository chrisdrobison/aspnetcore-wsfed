namespace AspNetCore.Authentication.WsFederation
{
    /// <summary>
    ///     Default values related to WsFederation authentication middleware
    /// </summary>
    public static class WsFederationAuthenticationDefaults
    {
        /// <summary>
        ///     The default value used for WsFederationAuthenticationOptions.AuthenticationType
        /// </summary>
        public const string AuthenticationType = "Federation";

        /// <summary>
        ///     The prefix used to provide a default WsFederationAuthenticationOptions.CookieName
        /// </summary>
        public const string CookiePrefix = "WsFederation.";

        /// <summary>
        ///     The prefix used to provide a default WsFederationAuthenticationOptions.CookieName
        /// </summary>
        public const string CookieName = "WsFederationAuth";

        /// <summary>
        ///     The default value for WsFederationAuthenticationOptions.Caption.
        /// </summary>
        public const string Caption = "WsFederation";

        internal const string WctxKey = "WsFedOwinState";
    }
}