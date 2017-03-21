using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Contrib.Authentication.WsFederation.Events;

namespace Microsoft.AspNetCore.Contrib.Authentication.WsFederation
{
    /// <summary>
    /// Specifies events which the <see cref="WsFederationAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public class WsFederationEvents : RemoteAuthenticationEvents, IWsFederationEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } =
            context => TaskCache.CompletedTask;

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = 
            context => TaskCache.CompletedTask;

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
        /// </summary>
        public Func<RedirectContext, Task> OnRedirectToIdentityProvider { get; set; } =
            context => TaskCache.CompletedTask;

        /// <summary>
        /// Invoked with the security token that has been extracted from the protocol message.
        /// </summary>
        public Func<SecurityTokenContext, Task> OnSecurityTokenReceived { get; set; } =
            context => TaskCache.CompletedTask;

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<SecurityTokenValidatedContext, Task> OnSecurityTokenValidated { get; set; } =
            context => TaskCache.CompletedTask;


        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

        public Task RedirectToIdentityProvider(RedirectContext context) => OnRedirectToIdentityProvider(context);

        public Task SecurityTokenReceived(SecurityTokenContext context) => OnSecurityTokenReceived(context);

        public Task SecurityTokenValidated(SecurityTokenValidatedContext context) => OnSecurityTokenValidated(context);
    }
}