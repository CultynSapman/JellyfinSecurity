using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [v2.5.10] (issue #55) Surfaces account lockout at the LOGIN step so the user
/// sees a clear "temporarily locked" message instead of Jellyfin's generic
/// "Invalid username or password".
///
/// The provider (TwoFactorAuthProvider) enforces the lockout by throwing an
/// AuthenticationException, but Jellyfin's ExceptionMiddleware strips the
/// message in production and returns a generic 401 ("Error processing
/// request."), so the web client can't distinguish a lockout from a wrong
/// password. This middleware checks lockout for the submitted username on
/// POST /Users/AuthenticateByName and, when locked, short-circuits with a
/// recognizable 401 JSON body ({"accountLocked":true,...}). inject.js detects
/// that marker (the same way it detects twoFactorRequired) and shows a toast.
///
/// Fails OPEN on internal errors (a store or lookup that throws), so a bug here
/// can never block legitimate logins. It fails CLOSED on a request body it
/// cannot read the way Jellyfin binds it, because passing that through skipped
/// the lockout entirely. IsLockedOutAsync honours the admin exemption, so an
/// exempt administrator is never blocked.
///
/// It is also the per-IP brute-force hook for password sign-in: banned IPs are
/// refused before the password is tested, and every wrong password feeds the
/// IP ban counter (TwoFactorAuthProvider only sees plugin-routed users).
/// </summary>
public class LockoutMessageMiddleware
{
    private readonly RequestDelegate _next;
    private readonly UserTwoFactorStore _store;
    private readonly IUserManager _userManager;
    private readonly OidcLoginTokenStore _bridgeTokens;
    private readonly IpBanService _ipBans;
    private readonly ILogger<LockoutMessageMiddleware> _logger;

    public LockoutMessageMiddleware(
        RequestDelegate next,
        UserTwoFactorStore store,
        IUserManager userManager,
        OidcLoginTokenStore bridgeTokens,
        IpBanService ipBans,
        ILogger<LockoutMessageMiddleware> logger)
    {
        _next = next;
        _store = store;
        _userManager = userManager;
        _bridgeTokens = bridgeTokens;
        _ipBans = ipBans;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var config = Plugin.Instance?.Configuration;

        // Only instrument Jellyfin's password sign-in endpoints. Everything
        // else flows straight through untouched.
        if (!TryMatchPasswordAuthEndpoint(context, out var routeUserId) || config?.Enabled != true)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // 00. IP BAN GATE. A banned source is refused BEFORE its password is
        //     tested. Previously the ban was only checked after Jellyfin had
        //     already accepted the password (in TwoFactorEnforcementMiddleware),
        //     so a banned IP could keep guessing, and the distinct "IP blocked"
        //     reply it got on a correct guess confirmed the password.
        var clientIp = BypassEvaluator.ResolveClientIp(context);
        if (!string.IsNullOrEmpty(clientIp) && _ipBans.CheckBanned(clientIp) is { } ban)
        {
            _logger.LogWarning("[2FA] Login refused: IP {Ip} is banned until {ExpiresAt}.", clientIp, ban.ExpiresAt);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(new
                {
                    message = "This IP address is temporarily blocked.",
                    ipBanned = true,
                    expiresAt = ban.ExpiresAt,
                }))
                .ConfigureAwait(false);
            return;
        }

        // Read the submitted credentials once. The two endpoints carry them
        // differently: AuthenticateByName posts a JSON body, while the obsolete
        // by-id form takes ?pw= and names the account by route GUID instead of
        // by username. A body that can't be read the way Jellyfin binds it is
        // refused (see PeekCredentialsAsync).
        string? username;
        string? password;
        Jellyfin.Database.Implementations.Entities.User? user;
        if (routeUserId != Guid.Empty)
        {
            // StringValues.ToString() joins duplicates with ',', which can only
            // ever differ from what Jellyfin's model binder resolves in the
            // direction of NOT matching a real password or a real bridge token
            // -- i.e. it fails closed, never open.
            var queryPw = context.Request.Query["pw"].ToString();
            password = string.IsNullOrEmpty(queryPw) ? null : queryPw;
            user = ResolveUserByIdSafe(routeUserId);
            username = user?.Username;
        }
        else
        {
            CredentialReadStatus readStatus;
            (readStatus, username, password) = await PeekCredentialsAsync(context.Request).ConfigureAwait(false);
            if (readStatus != CredentialReadStatus.Ok)
            {
                // Fail CLOSED: a body we can't read the way Jellyfin binds it
                // would otherwise reach the password check unthrottled.
                // Genuine clients send a small UTF-8 JSON object, so nothing
                // legitimate lands here.
                _logger.LogWarning("[2FA] Login refused: unreadable sign-in body ({Status}) from {Ip}.", readStatus, clientIp ?? "(unknown)");
                RecordIpFailure(clientIp, null);
                context.Response.StatusCode = readStatus == CredentialReadStatus.TooLarge
                    ? StatusCodes.Status413PayloadTooLarge
                    : StatusCodes.Status400BadRequest;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"message\":\"Invalid sign-in request.\"}").ConfigureAwait(false);
                return;
            }

            user = ResolveUserSafe(username);
        }

        // 0. EMPTY-PASSWORD GATE [v2.5.10] (issue #68, CWabbity). The provider
        //    enforces BlockEmptyPasswordLogin too, but ONLY for plugin-routed
        //    users (OIDC/passkey). Normal default-provider users never reach it,
        //    so a null-hash account could still be signed into with a blank
        //    password via this endpoint. Enforce it here for EVERY sign-in. OIDC
        //    bridge tokens are non-empty, so this never blocks SSO.
        if (config.BlockEmptyPasswordLogin && string.IsNullOrWhiteSpace(password))
        {
            _logger.LogWarning("[2FA] Login refused: empty password blocked (BlockEmptyPasswordLogin) for '{User}'.", username ?? "(unknown)");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Signing in with an empty password is not allowed. Please enter your password.\",\"emptyPasswordBlocked\":true}")
                .ConfigureAwait(false);
            return;
        }

        // 0b. DISABLE-PASSWORD-LOGIN GATE [v2.5.11] (issue #69, ZEROX7). When the
        //     admin has turned off password sign-in, refuse it here so only
        //     OIDC/SSO + Quick Connect remain. Three things are NEVER blocked:
        //     (a) OIDC bridge tokens — SSO completes via this same endpoint with
        //         a one-time token as the "password", so a token this server
        //         actually minted is let through. (Quick Connect uses a
        //         different endpoint entirely and is never matched here.)
        //         [v2.5.22] This asks the store (IsKnownBridgeToken) rather than
        //         testing the "oidcbr_" prefix. The prefix test meant any user
        //         could opt out of this server-wide policy simply by choosing a
        //         password that starts with that string.
        //     (b) the configured escape hatches (admin / LAN / exempt CIDRs).
        //     The plugin's own /TwoFactorAuth/Login page is unaffected either way.
        if (config.DisablePasswordLogin
            && !_bridgeTokens.IsKnownBridgeToken(password)
            && !IsPasswordLoginExempt(context, config, user))
        {
            _logger.LogWarning("[2FA] Password sign-in refused (DisablePasswordLogin) for '{User}'.", username ?? "(unknown)");
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Password sign-in is disabled on this server. Please sign in with your identity provider.\",\"passwordLoginDisabled\":true}")
                .ConfigureAwait(false);
            return;
        }

        // 1. PRE-CHECK: a locked account is refused BEFORE the password is even
        //    checked, with a recognizable body so inject.js can show a
        //    "temporarily locked" message (Jellyfin strips the provider's
        //    AuthenticationException message in production). IsLockedOutAsync
        //    honours the admin exemption, so an exempt admin is never blocked.
        if (user is not null && await IsLockedSafeAsync(user.Id).ConfigureAwait(false))
        {
            _logger.LogWarning("[2FA] Login refused for locked account '{User}'.", user.Username);
            // Spraying guesses at already-locked accounts is still guessing.
            RecordIpFailure(clientIp, user);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                "{\"message\":\"Your account is temporarily locked due to too many failed sign-in attempts. Please try again later.\",\"accountLocked\":true}")
                .ConfigureAwait(false);
            return;
        }

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch (MediaBrowser.Controller.Authentication.AuthenticationException)
        {
            // Bad credentials surface as a thrown AuthenticationException here
            // when this middleware sits INSIDE Jellyfin's exception handler
            // (the common ordering). Record the failed attempt, then let it
            // propagate so the normal 401 is produced. We do NOT also run the
            // status-based branch below in this case (we re-throw), so there's
            // no double count.
            RecordIpFailure(clientIp, user);
            if (user is not null)
            {
                try
                {
                    await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[2FA] lockout record (exception path) failed (non-fatal)");
                }
            }

            throw;
        }

        // 2. POST: record the outcome so the per-account lockout actually tracks
        //    PASSWORD attempts. The plugin's IAuthenticationProvider is NOT
        //    invoked for users on Jellyfin's default password provider (only
        //    OIDC/passkey users are routed to it), so this middleware is the
        //    single universal hook for "wrong password -> lockout". This branch
        //    covers pipeline orderings where the auth failure arrives as a 401
        //    status rather than a thrown exception. Admin accounts are exempt
        //    inside RecordFailedAttemptAsync (the counter still increments for
        //    visibility, but LockoutEnd is never set).
        //
        //    The IP counter is fed here too, and BEFORE the user-null return:
        //    guessing against usernames that don't exist is still brute force.
        //    Before this change wrong passwords for default-provider users never
        //    reached IpBanService at all, so the "Fail2Ban-style" ban could not
        //    trigger on ordinary password guessing. On success we deliberately do
        //    NOT reset the IP counter: one valid account would otherwise let an
        //    attacker wipe their failure count between guesses at other accounts.
        if (context.Response.StatusCode == StatusCodes.Status401Unauthorized)
        {
            RecordIpFailure(clientIp, user);
        }

        if (user is null)
        {
            return;
        }

        try
        {
            var status = context.Response.StatusCode;
            if (status is >= 200 and < 300)
            {
                await _store.ResetFailedAttemptsAsync(user.Id).ConfigureAwait(false);
            }
            else if (status == StatusCodes.Status401Unauthorized)
            {
                await _store.RecordFailedAttemptAsync(user.Id).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] lockout record/reset after login failed (non-fatal)");
        }
    }

    /// <summary>[v2.5.11] (#69) true when password login should still be allowed
    /// for this request despite DisablePasswordLogin — via the admin, LAN, or
    /// explicit-CIDR escape hatches. Fails OPEN (returns true) on any error so a
    /// bug here can never lock everyone out of password sign-in.</summary>
    private bool IsPasswordLoginExempt(HttpContext context, PluginConfiguration config, Jellyfin.Database.Implementations.Entities.User? user)
    {
        try
        {
            // Admin escape hatch (toggleable).
            if (config.AllowAdminPasswordLogin && user is not null
                && user.HasPermission(PermissionKind.IsAdministrator))
            {
                return true;
            }

            var clientIp = BypassEvaluator.ResolveClientIp(context);
            if (string.IsNullOrEmpty(clientIp))
            {
                return false;
            }

            // LAN escape hatch (toggleable) — "disable for remote users only".
            if (config.AllowPasswordLoginOnLan && config.LanBypassCidrs is { Length: > 0 })
            {
                foreach (var cidr in config.LanBypassCidrs)
                {
                    if (BypassEvaluator.IsIpInCidr(clientIp, cidr))
                    {
                        return true;
                    }
                }
            }

            // Explicit exempt CIDRs.
            if (config.PasswordLoginExemptCidrs is { Length: > 0 })
            {
                foreach (var cidr in config.PasswordLoginExemptCidrs)
                {
                    if (BypassEvaluator.IsIpInCidr(clientIp, cidr))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] password-login-exempt check threw; allowing the request");
            return true;
        }
    }

    /// <summary>Jellyfin's obsolete by-id password endpoint:
    /// POST /Users/{userId}/Authenticate?pw=... . Tolerates a configured Jellyfin
    /// BaseUrl prefix, which 10.11.x leaves in Request.Path, and both the dashed
    /// (36-char) and undashed (32-char) GUID forms that Guid.TryParse — and
    /// therefore ASP.NET's :guid route constraint — accept.</summary>
    private static readonly Regex ObsoleteByIdAuthPath = new(
        @"/Users/([0-9a-fA-F-]{32,36})/Authenticate$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    /// <summary>[v2.5.22] True when this request is one of Jellyfin's TWO
    /// password sign-in endpoints. <paramref name="routeUserId"/> comes back as
    /// the route GUID on the obsolete by-id form and Guid.Empty on
    /// AuthenticateByName, which is how the caller knows where to read the
    /// submitted password from.
    ///
    /// SECURITY: matching only AuthenticateByName left a real hole, not a
    /// theoretical one. Jellyfin's UserController still routes
    /// POST /Users/{userId}/Authenticate?pw=..., it carries no [Authorize]
    /// exactly like AuthenticateByName, and it reaches the same authentication
    /// code as an in-process METHOD call — so no path-matching middleware ever
    /// sees a second request. Everything enforced here (DisablePasswordLogin,
    /// BlockEmptyPasswordLogin, and per-account lockout INCLUDING the failure
    /// counter, which for default-provider users has no other hook) was skipped
    /// on it, leaving an unthrottled and unaudited password-guessing path. It is
    /// [ApiExplorerSettings(IgnoreApi = true)] so it never shows up in the
    /// OpenAPI document, and GET /Users/Public hands out the GUIDs it needs
    /// anonymously.
    ///
    /// Quick Connect is deliberately NOT matched: it is not password sign-in and
    /// has to keep working while DisablePasswordLogin is on.</summary>
    internal static bool TryMatchPasswordAuthEndpoint(HttpContext context, out Guid routeUserId)
    {
        routeUserId = Guid.Empty;
        return HttpMethods.IsPost(context.Request.Method)
            && TryMatchPasswordAuthPath(context.Request.Path.Value, out routeUserId);
    }

    /// <summary>Path-only half, split out so the routing contract can be tested
    /// without standing up an HttpContext.</summary>
    internal static bool TryMatchPasswordAuthPath(string? rawPath, out Guid routeUserId)
    {
        routeUserId = Guid.Empty;
        var path = (rawPath ?? string.Empty).TrimEnd('/');
        if (path.EndsWith("/Users/AuthenticateByName", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var match = ObsoleteByIdAuthPath.Match(path);
        return match.Success && Guid.TryParse(match.Groups[1].Value, out routeUserId);
    }

    /// <summary>Feed one failed password attempt into the per-IP ban counter.
    /// Skipped for users routed to the plugin's own authentication provider,
    /// because TwoFactorAuthProvider already records those failures itself and
    /// counting here as well would ban twice as fast. Never throws.</summary>
    private void RecordIpFailure(string? clientIp, Jellyfin.Database.Implementations.Entities.User? user)
    {
        if (string.IsNullOrEmpty(clientIp) || IsPluginRoutedUser(user))
        {
            return;
        }

        try
        {
            _ipBans.RecordFailure(clientIp);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] IP failure record failed (non-fatal)");
        }
    }

    internal static bool IsPluginRoutedUser(Jellyfin.Database.Implementations.Entities.User? user)
        => user is not null
            && string.Equals(user.AuthenticationProviderId, SignInProviderRestore.PluginProviderId, StringComparison.OrdinalIgnoreCase);

    private async Task<bool> IsLockedSafeAsync(Guid userId)
    {
        try
        {
            return await _store.IsLockedOutAsync(userId).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Fail OPEN — never block a login because the lockout check threw.
            _logger.LogDebug(ex, "[2FA] lockout pre-check threw; passing the request through");
            return false;
        }
    }

    private Jellyfin.Database.Implementations.Entities.User? ResolveUserByIdSafe(Guid userId)
    {
        try
        {
            return _userManager.GetUserById(userId);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] could not resolve attempted login user by id; passing through");
            return null;
        }
    }

    private Jellyfin.Database.Implementations.Entities.User? ResolveUserSafe(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        try
        {
            return _userManager.GetUserByName(username);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[2FA] could not resolve attempted login user; passing through");
            return null;
        }
    }

    /// <summary>Largest AuthenticateByName body we will read. A real sign-in is
    /// well under 1 KB; anything bigger is refused rather than passed through.</summary>
    internal const int MaxCredentialBodyBytes = 64 * 1024;

    /// <summary>Outcome of reading the submitted credentials.</summary>
    internal enum CredentialReadStatus
    {
        /// <summary>Body read and parsed the same way Jellyfin binds it.</summary>
        Ok,

        /// <summary>Body is larger than <see cref="MaxCredentialBodyBytes"/>.</summary>
        TooLarge,

        /// <summary>Body could not be decoded or parsed as Jellyfin would.</summary>
        Unreadable,
    }

    /// <summary>Read the JSON body's Username + Pw without consuming it for the
    /// downstream pipeline (EnableBuffering + rewind).
    ///
    /// SECURITY: this used to return (null, null) for any body over 8 KB or any
    /// body it could not parse, and the caller treated that as a pass-through.
    /// Jellyfin itself happily binds a padded body, a UTF-16 body, or one whose
    /// property names are in a different case, so each of those reached the
    /// password check with no lockout pre-check and no failure recorded —
    /// unlimited guessing. A body we cannot read is now reported to the caller,
    /// which refuses the request instead of waving it through.</summary>
    private static async Task<(CredentialReadStatus Status, string? Username, string? Password)> PeekCredentialsAsync(HttpRequest request)
    {
        try
        {
            if (request.ContentLength is > MaxCredentialBodyBytes)
            {
                return (CredentialReadStatus.TooLarge, null, null);
            }

            request.EnableBuffering();

            // Read at most one byte past the cap so a chunked body (no
            // Content-Length) can't make us buffer without bound.
            var buffer = new byte[MaxCredentialBodyBytes + 1];
            var total = 0;
            int read;
            while (total < buffer.Length
                && (read = await request.Body.ReadAsync(buffer.AsMemory(total, buffer.Length - total)).ConfigureAwait(false)) > 0)
            {
                total += read;
            }

            request.Body.Position = 0;

            if (total > MaxCredentialBodyBytes)
            {
                return (CredentialReadStatus.TooLarge, null, null);
            }

            var encoding = ResolveRequestEncoding(request.ContentType);
            if (encoding is null)
            {
                return (CredentialReadStatus.Unreadable, null, null);
            }

            var body = encoding.GetString(buffer, 0, total);
            var (ok, username, password) = ParseCredentials(body);
            return (ok ? CredentialReadStatus.Ok : CredentialReadStatus.Unreadable, username, password);
        }
        catch
        {
            return (CredentialReadStatus.Unreadable, null, null);
        }
    }

    /// <summary>Encoding for the request body, following the Content-Type
    /// charset the way ASP.NET's JSON input formatter does (UTF-8 by default,
    /// and it transcodes UTF-16 too). Returns null for a charset .NET cannot
    /// resolve, which the caller treats as unreadable.</summary>
    internal static Encoding? ResolveRequestEncoding(string? contentType)
    {
        string? charset = null;
        if (!string.IsNullOrWhiteSpace(contentType)
            && Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(contentType, out var mediaType))
        {
            charset = mediaType.Charset.HasValue ? mediaType.Charset.Value : null;
        }

        if (string.IsNullOrWhiteSpace(charset))
        {
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);
        }

        try
        {
            return Encoding.GetEncoding(charset.Trim('"'));
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Pull Username and Pw out of an AuthenticateByName body using the
    /// same rules Jellyfin's model binder applies, so the account this
    /// middleware throttles is always the account Jellyfin authenticates:
    /// <list type="bullet">
    /// <item>property names match case-insensitively (ASP.NET's MVC JSON
    /// options start from JsonSerializerDefaults.Web and Jellyfin never turns
    /// that off);</item>
    /// <item>only <c>Username</c> and <c>Pw</c> are bound — the DTO has no other
    /// credential fields;</item>
    /// <item>a repeated property takes the LAST value, as the deserializer
    /// does;</item>
    /// <item>numbers and booleans are read as their raw text (Jellyfin's
    /// JsonStringConverter), null as null.</item>
    /// </list>
    /// Returns ok=false for anything Jellyfin would not bind cleanly (not an
    /// object, object/array values, invalid JSON), which callers refuse.</summary>
    internal static (bool Ok, string? Username, string? Password) ParseCredentials(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return (false, null, null);
        }

        try
        {
            // A leading BOM survives decoding as U+FEFF; System.Text.Json skips
            // a UTF-8 BOM, so do the same.
            using var doc = JsonDocument.Parse(body.TrimStart('﻿'));
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return (false, null, null);
            }

            string? username = null;
            string? password = null;
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                var isUser = string.Equals(prop.Name, "Username", StringComparison.OrdinalIgnoreCase);
                var isPw = string.Equals(prop.Name, "Pw", StringComparison.OrdinalIgnoreCase);
                if (!isUser && !isPw)
                {
                    continue;
                }

                if (!TryReadBoundString(prop.Value, out var value))
                {
                    return (false, null, null);
                }

                if (isUser)
                {
                    username = value;
                }
                else
                {
                    password = value;
                }
            }

            return (true, username, password);
        }
        catch (JsonException)
        {
            return (false, null, null);
        }
    }

    private static bool TryReadBoundString(JsonElement el, out string? value)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.String:
                value = el.GetString();
                return true;
            case JsonValueKind.Null:
                value = null;
                return true;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                value = el.GetRawText();
                return true;
            default:
                value = null;
                return false;
        }
    }
}
