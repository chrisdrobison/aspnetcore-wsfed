using System.Threading.Tasks;
using AspNetCoreWsFed.Events;
using Microsoft.AspNetCore.Authentication;

namespace AspNetCoreWsFed
{
    /// <summary>
    /// Specifies events which the <see cref="WsFederationAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public class WsFederationEvents : RemoteAuthenticationEvents, IWsFederationEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Task AuthenticationFailed(AuthenticationFailedContext context)
        {
            return Task.FromResult(0);
        }

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Task MessageReceived(MessageReceivedContext context)
        {
            return Task.FromResult(0);
        }

        /// <summary>
        /// Invoked to manipulate redirects to the identity provider for SignIn, SignOut, or Challenge.
        /// </summary>
        public Task RedirectToIdentityProvider(RedirectContext context)
        {
            return Task.FromResult(0);
        }

        /// <summary>
        /// Invoked with the security token that has been extracted from the protocol message.
        /// </summary>
        public Task SecurityTokenReceived(SecurityTokenContext context)
        {
            return Task.FromResult(0);
        }

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Task SecurityTokenValidated(SecurityTokenValidatedContext context)
        {
            return Task.FromResult(0);
        }
    }
}