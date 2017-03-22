using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using AspNetCore.Authentication.WsFederation.Events;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Extensions;
using Microsoft.IdentityModel.Protocols;

namespace AspNetCore.Authentication.WsFederation
{
    public class WsFederationAuthenticationHandler : RemoteAuthenticationHandler<WsFederationAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private WsFederationConfiguration _configuration;

        public WsFederationAuthenticationHandler(ILogger logger)
        {
            _logger = logger;
        }

        /// <summary>
        ///     Authenticate the user identity with the identity provider.
        ///     The method process the request on the endpoint defined by CallbackPath.
        /// </summary>
        protected override async Task<AuthenticateResult> HandleRemoteAuthenticateAsync()
        {
            // Allow login to be constrained to a specific path.
            if (Options.CallbackPath.HasValue && Options.CallbackPath != Request.PathBase + Request.Path)
            {
                return null;
            }

            WsFederationMessage wsFederationMessage = null;

            // assumption: if the ContentType is "application/x-www-form-urlencoded" it should be safe to read as it is small.
            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(Request.ContentType)
                // May have media/type; charset=utf-8, allow partial match.
                &&
                Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
                && Request.Body.CanRead)
            {
                if (!Request.Body.CanSeek)
                {
                    Logger.LogDebug("Buffering request body");
                    // Buffer in case this body was not meant for us.
                    var memoryStream = new MemoryStream();
                    await Request.Body.CopyToAsync(memoryStream);
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    Request.Body = memoryStream;
                }
                var form = await Request.ReadFormAsync();
                Request.Body.Seek(0, SeekOrigin.Begin);

                // TODO: a delegate on WsFederationAuthenticationOptions would allow for users to hook their own custom message.
                wsFederationMessage = new WsFederationMessage(
                    form.Select(pair => new KeyValuePair<string, string[]>(pair.Key, pair.Value.ToArray())));
            }

            if (wsFederationMessage == null || !wsFederationMessage.IsSignInMessage)
            {
                return null;
            }

            try
            {
                var messageReceivedContext = await RunMessageReceivedEventAsync(wsFederationMessage);
                AuthenticateResult result;
                if (messageReceivedContext.CheckEventResult(out result))
                {
                    return result;
                }

                if (wsFederationMessage.Wresult == null)
                {
                    _logger.LogWarning("Received a sign-in message without a WResult.");
                    return null;
                }

                var token = wsFederationMessage.GetToken();
                if (string.IsNullOrWhiteSpace(token))
                {
                    _logger.LogWarning("Received a sign-in message without a token.");
                    return null;
                }

                var securityTokenContext = await RunSecurityTokenReceivedEventAsync(wsFederationMessage);
                if (securityTokenContext.CheckEventResult(out result))
                {
                    return result;
                }

                if (_configuration == null)
                {
                    _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
                }

                // Copy and augment to avoid cross request race conditions for updated configurations.
                var tvp = Options.TokenValidationParameters.Clone();
                IEnumerable<string> issuers = new[] {_configuration.Issuer};
                tvp.ValidIssuers = tvp.ValidIssuers?.Concat(issuers) ?? issuers;
                tvp.IssuerSigningKeys = tvp.IssuerSigningKeys?.Concat(_configuration.SigningKeys) ??
                                        _configuration.SigningKeys;

                SecurityToken parsedToken;
                var principal = Options.SecurityTokenHandlers.ValidateToken(token, tvp, out parsedToken);

                // Retrieve our cached redirect uri
                var state = wsFederationMessage.Wctx;
                // WsFed allows for uninitiated logins, state may be missing.
                var properties = GetPropertiesFromWctx(state);
                var ticket = new AuthenticationTicket(principal, properties,
                    Options.AuthenticationScheme);

                if (Options.UseTokenLifetime)
                {
                    // Override any session persistence to match the token lifetime.
                    var issued = parsedToken.ValidFrom;
                    if (issued != DateTime.MinValue)
                    {
                        ticket.Properties.IssuedUtc = issued.ToUniversalTime();
                    }
                    var expires = parsedToken.ValidTo;
                    if (expires != DateTime.MinValue)
                    {
                        ticket.Properties.ExpiresUtc = expires.ToUniversalTime();
                    }
                    ticket.Properties.AllowRefresh = false;
                }

                var securityTokenValidatedNotification = await RunSecurityTokenValidatedEventAsync(wsFederationMessage,
                    ticket);
                return securityTokenValidatedNotification.CheckEventResult(out result)
                    ? result
                    : AuthenticateResult.Success(ticket);
            }
            catch (Exception exception)
            {
                _logger.LogError("Exception occurred while processing message: ", exception);

                // Refresh the configuration for exceptions that may be caused by key rollovers. The user can also request a refresh in the notification.
                if (Options.RefreshOnIssuerKeyNotFound &&
                    exception.GetType() == typeof(SecurityTokenSignatureKeyNotFoundException))
                {
                    Options.ConfigurationManager.RequestRefresh();
                }

                var authenticationFailedNotification = await RunAuthenticationFailedEventAsync(wsFederationMessage,
                    exception);
                return authenticationFailedNotification.CheckEventResult(out AuthenticateResult result)
                    ? result
                    : AuthenticateResult.Fail(exception);
            }
        }

        /// <summary>
        ///     Override this method to deal with 401 challenge concerns, if an authentication scheme in question
        ///     deals an authentication interaction as part of it's request flow. (like adding a response header, or
        ///     changing the 401 result to 302 of a login page or external sign-in location.)
        /// </summary>
        /// <param name="context"></param>
        /// <returns>True if no other handlers should be called</returns>
        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Logger.LogTrace($"Entering {nameof(WsFederationAuthenticationHandler)}'s HandleUnauthorizedAsync");

            if (_configuration == null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
            }

            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;

            var properties = new AuthenticationProperties(context.Properties);
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            var wsFederationMessage = new WsFederationMessage
            {
                IssuerAddress = _configuration.TokenEndpoint ?? string.Empty,
                Wtrealm = Options.Wtrealm,
                Wctx =
                    $"{WsFederationAuthenticationDefaults.WctxKey}={Uri.EscapeDataString(Options.StateDataFormat.Protect(properties))}",
                Wa = WsFederationActions.SignIn,
                Wreply = BuildWreply(Options.CallbackPath)
            };

            if (!string.IsNullOrWhiteSpace(Options.Wreply))
            {
                wsFederationMessage.Wreply = Options.Wreply;
            }

            var redirectContext = new RedirectContext(Context, Options)
            {
                ProtocolMessage = wsFederationMessage,
                Properties = properties
            };

            await Options.Events.RedirectToIdentityProvider(redirectContext);
            if (redirectContext.HandledResponse)
            {
                Logger.LogDebug("RedirectContext.HandledResponse");
                return true;
            }
            if (redirectContext.Skipped)
            {
                Logger.LogDebug("RedirectContext.Skipped");
                return false;
            }

            var redirectUri = redirectContext.ProtocolMessage.CreateSignInUrl();
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                Logger.LogWarning($"The sign-in redirect URI is malformed: {redirectUri}");
            }
            Response.Redirect(redirectUri);
            return true;
        }

        /// <summary>
        ///     Handles signout
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        protected override async Task HandleSignOutAsync(SignOutContext context)
        {
            if (context == null)
            {
                return;
            }

            Logger.LogTrace($"Entering {nameof(WsFederationAuthenticationHandler)}'s HandleSignOutAsync");

            if (_configuration == null && Options.ConfigurationManager != null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.RequestAborted);
            }

            var wsFederationMessage = new WsFederationMessage
            {
                IssuerAddress = _configuration.TokenEndpoint ?? string.Empty,
                Wtrealm = Options.Wtrealm,
                Wa = WsFederationActions.SignOut
            };

            var properties = new AuthenticationProperties(context.Properties);
            if (!string.IsNullOrEmpty(properties?.RedirectUri))
            {
                wsFederationMessage.Wreply = properties.RedirectUri;
            }
            else if (!string.IsNullOrWhiteSpace(Options.SignOutWreply))
            {
                wsFederationMessage.Wreply = Options.SignOutWreply;
            }
            else if (!string.IsNullOrWhiteSpace(Options.Wreply))
            {
                wsFederationMessage.Wreply = Options.Wreply;
            }

            var redirectContext = new RedirectContext(Context, Options)
            {
                ProtocolMessage = wsFederationMessage
            };
            await Options.Events.RedirectToIdentityProvider(redirectContext);
            if (redirectContext.HandledResponse)
            {
                Logger.LogDebug("RedirectContext.HandledResponse");
                return;
            }
            if (redirectContext.Skipped)
            {
                Logger.LogDebug("RedirectContext.Skipped");
                return;
            }

            var redirectUri = redirectContext.ProtocolMessage.CreateSignOutUrl();
            if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
            {
                Logger.LogWarning($"The sign-out redirect URI is malformed: {redirectUri}");
            }
            Response.Redirect(redirectUri);
        }

        private AuthenticationProperties GetPropertiesFromWctx(string state)
        {
            AuthenticationProperties properties = null;
            if (!string.IsNullOrEmpty(state))
            {
                var pairs = ParseDelimited(state);
                List<string> values;
                if (pairs.TryGetValue(WsFederationAuthenticationDefaults.WctxKey, out values) && values.Count > 0)
                {
                    var value = values.First();
                    properties = Options.StateDataFormat.Unprotect(value);
                }
            }
            return properties;
        }

        private async Task<MessageReceivedContext> RunMessageReceivedEventAsync(WsFederationMessage message)
        {
            Logger.LogTrace($"MessageReceived: {message.BuildRedirectUrl()}");
            var messageReceivedContext = new MessageReceivedContext(Context, Options)
            {
                ProtocolMessage = message
            };

            await Options.Events.MessageReceived(messageReceivedContext);
            if (messageReceivedContext.HandledResponse)
            {
                Logger.LogDebug("MessageReceivedContext.HandledResponse");
            }
            else if (messageReceivedContext.Skipped)
            {
                Logger.LogDebug("MessageReceivedContext.Skipped");
            }

            return messageReceivedContext;
        }

        private async Task<SecurityTokenContext> RunSecurityTokenReceivedEventAsync(WsFederationMessage message)
        {
            Logger.LogTrace($"SecurityTokenReceived: {message.GetToken()}");
            var securityTokenContext = new SecurityTokenContext(Context, Options)
            {
                ProtocolMessage = message
            };

            await Options.Events.SecurityTokenReceived(securityTokenContext);
            if (securityTokenContext.HandledResponse)
            {
                Logger.LogDebug("SecurityTokenContext.HandledResponse");
            }
            else if (securityTokenContext.Skipped)
            {
                Logger.LogDebug("SecurityTokenContext.HandledResponse");
            }

            return securityTokenContext;
        }

        private async Task<SecurityTokenValidatedContext> RunSecurityTokenValidatedEventAsync(
            WsFederationMessage message,
            AuthenticationTicket ticket)
        {
            Logger.LogTrace($"SecurityTokenValidated: {ticket.AuthenticationScheme} {ticket.Principal.Identity.Name}");
            var securityTokenValidateContext = new SecurityTokenValidatedContext(Context, Options)
            {
                ProtocolMessage = message,
                Ticket = ticket
            };

            await Options.Events.SecurityTokenValidated(securityTokenValidateContext);
            if (securityTokenValidateContext.HandledResponse)
            {
                Logger.LogDebug("SecurityTokenValidatedContext.HandledResponse");
            }
            else if (securityTokenValidateContext.Skipped)
            {
                Logger.LogDebug("SecurityTokenValidatedContext.Skipped");
            }

            return securityTokenValidateContext;
        }

        private async Task<AuthenticationFailedContext> RunAuthenticationFailedEventAsync(WsFederationMessage message,
            Exception exception)
        {
            Logger.LogTrace("AuthenticationFailed");
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Options)
            {
                ProtocolMessage = message,
                Exception = exception
            };

            await Options.Events.AuthenticationFailed(authenticationFailedContext);
            if (authenticationFailedContext.HandledResponse)
            {
                Logger.LogDebug("AuthenticationFailedContext.HandledResponse");
            }
            else if (authenticationFailedContext.Skipped)
            {
                Logger.LogDebug("AuthenticationFailedContext.Skipped");
            }

            return authenticationFailedContext;
        }

        private string BuildWreply(string targetPath)
        {
            return Request.Scheme + "://" + Request.Host + OriginalPathBase + targetPath;
        }

        private static IDictionary<string, List<string>> ParseDelimited(string text)
        {
            char[] delimiters = {'&', ';'};
            var accumulator = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var textLength = text.Length;
            var equalIndex = text.IndexOf('=');
            if (equalIndex == -1)
            {
                equalIndex = textLength;
            }
            var scanIndex = 0;
            while (scanIndex < textLength)
            {
                var delimiterIndex = text.IndexOfAny(delimiters, scanIndex);
                if (delimiterIndex == -1)
                {
                    delimiterIndex = textLength;
                }
                if (equalIndex < delimiterIndex)
                {
                    while (scanIndex != equalIndex && char.IsWhiteSpace(text[scanIndex]))
                        ++scanIndex;
                    var name = text.Substring(scanIndex, equalIndex - scanIndex);
                    var value = text.Substring(equalIndex + 1, delimiterIndex - equalIndex - 1);

                    name = Uri.UnescapeDataString(name.Replace('+', ' '));
                    value = Uri.UnescapeDataString(value.Replace('+', ' '));

                    List<string> existing;
                    if (!accumulator.TryGetValue(name, out existing))
                    {
                        accumulator.Add(name, new List<string>(1) {value});
                    }
                    else
                    {
                        existing.Add(value);
                    }

                    equalIndex = text.IndexOf('=', delimiterIndex);
                    if (equalIndex == -1)
                    {
                        equalIndex = textLength;
                    }
                }
                scanIndex = delimiterIndex + 1;
            }
            return accumulator;
        }
    }
}