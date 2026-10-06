using System.Text;
using System.Text.Json;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Regression cover for the per-account lockout bypass in
/// <see cref="LockoutMessageMiddleware"/>.
///
/// The middleware read the sign-in body itself to learn which account to
/// throttle, but matched only a handful of exact property spellings and gave up
/// on bodies over 8 KB. Jellyfin binds property names case-insensitively and
/// accepts large bodies, so <c>{"USERNAME":"bob","Pw":"guess"}</c> or a padded
/// body reached the password check with no lockout pre-check and no failure
/// recorded: unlimited guessing. These tests pin the parser to Jellyfin's
/// binding rules so the throttled account is always the authenticated one.
/// </summary>
public class LockoutCredentialParsingTests
{
    [Theory]
    [InlineData("""{"Username":"bob","Pw":"x"}""")]
    [InlineData("""{"username":"bob","pw":"x"}""")]
    [InlineData("""{"USERNAME":"bob","PW":"x"}""")]
    [InlineData("""{"uSeRnAmE":"bob","pW":"x"}""")]
    public void PropertyNames_AreMatchedCaseInsensitively(string body)
    {
        var (ok, user, pw) = LockoutMessageMiddleware.ParseCredentials(body);
        Assert.True(ok);
        Assert.Equal("bob", user);
        Assert.Equal("x", pw);
    }

    [Fact]
    public void DuplicateProperty_LastValueWins_LikeTheDeserializer()
    {
        // An attacker can't name one account to the throttle and another to
        // Jellyfin by repeating the property in different cases.
        var body = """{"Username":"decoy","USERNAME":"victim","Pw":"x"}""";
        var (ok, user, _) = LockoutMessageMiddleware.ParseCredentials(body);
        Assert.True(ok);
        Assert.Equal("victim", user);
    }

    [Theory]
    [InlineData("""{"Username":"bob","Pw":"x"}""")]
    [InlineData("""{"USERNAME":"bob","pw":"x"}""")]
    [InlineData("""{"Username":"decoy","username":"victim","Pw":"a","PW":"b"}""")]
    [InlineData("""{"Pw":"x"}""")]
    [InlineData("""{"Username":null,"Pw":"x"}""")]
    public void Parser_AgreesWith_AspNetWebDefaultsBinding(string body)
    {
        // ASP.NET's MVC JSON options start from JsonSerializerDefaults.Web,
        // which Jellyfin keeps (it only overrides naming policy, converters and
        // a few unrelated flags).
        var bound = JsonSerializer.Deserialize<AuthenticateUserByNameShape>(
            body, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var (ok, user, pw) = LockoutMessageMiddleware.ParseCredentials(body);

        Assert.True(ok);
        Assert.NotNull(bound);
        Assert.Equal(bound!.Username, user);
        Assert.Equal(bound.Pw, pw);
    }

    [Theory]
    [InlineData("""{"Username":123,"Pw":true}""", "123", "true")]
    [InlineData("""{"Username":1.5e3,"Pw":false}""", "1.5e3", "false")]
    public void NumbersAndBooleans_AreReadAsRawText_LikeJellyfinsStringConverter(string body, string expectedUser, string expectedPw)
    {
        var (ok, user, pw) = LockoutMessageMiddleware.ParseCredentials(body);
        Assert.True(ok);
        Assert.Equal(expectedUser, user);
        Assert.Equal(expectedPw, pw);
    }

    [Fact]
    public void UnrelatedFields_AreIgnored_NotTreatedAsCredentials()
    {
        // Only Username and Pw exist on Jellyfin's DTO.
        var (ok, user, pw) = LockoutMessageMiddleware.ParseCredentials(
            """{"Name":"other","Password":"other","Username":"bob","Pw":"x"}""");
        Assert.True(ok);
        Assert.Equal("bob", user);
        Assert.Equal("x", pw);
    }

    [Fact]
    public void PaddedBody_StillYieldsTheUser()
    {
        // Whitespace padding past the old 8 KB give-up point.
        var body = """{"Username":"bob",""" + new string(' ', 20_000) + "\"Pw\":\"x\"}";
        var (ok, user, _) = LockoutMessageMiddleware.ParseCredentials(body);
        Assert.True(ok);
        Assert.Equal("bob", user);
    }

    [Fact]
    public void LeadingBom_IsTolerated()
    {
        var (ok, user, _) = LockoutMessageMiddleware.ParseCredentials("﻿{\"Username\":\"bob\",\"Pw\":\"x\"}");
        Assert.True(ok);
        Assert.Equal("bob", user);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("\"bob\"")]
    [InlineData("""{"Username":{"x":1},"Pw":"x"}""")]
    [InlineData("""{"Username":["bob"],"Pw":"x"}""")]
    [InlineData("""{"Username":"bob","Pw":"x",}""")]
    public void BodiesJellyfinWouldNotBindCleanly_AreReportedUnreadable(string body)
    {
        // The middleware refuses these instead of passing them through.
        var (ok, _, _) = LockoutMessageMiddleware.ParseCredentials(body);
        Assert.False(ok);
    }

    [Fact]
    public void Utf16Body_IsDecodedFromTheDeclaredCharset()
    {
        // ASP.NET's JSON input formatter transcodes UTF-16, so the throttle has
        // to as well or a UTF-16 body would read as garbage and slip past.
        var encoding = LockoutMessageMiddleware.ResolveRequestEncoding("application/json; charset=utf-16");
        Assert.NotNull(encoding);

        var bytes = Encoding.Unicode.GetBytes("""{"Username":"bob","Pw":"x"}""");
        var (ok, user, _) = LockoutMessageMiddleware.ParseCredentials(encoding!.GetString(bytes));
        Assert.True(ok);
        Assert.Equal("bob", user);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("application/json")]
    [InlineData("application/json; charset=utf-8")]
    [InlineData("application/json; charset=\"utf-8\"")]
    public void Encoding_DefaultsToOrHonoursUtf8(string? contentType)
    {
        var encoding = LockoutMessageMiddleware.ResolveRequestEncoding(contentType);
        Assert.NotNull(encoding);
        Assert.Equal(Encoding.UTF8.WebName, encoding!.WebName);
    }

    [Fact]
    public void UnknownCharset_IsUnreadable()
    {
        Assert.Null(LockoutMessageMiddleware.ResolveRequestEncoding("application/json; charset=not-a-charset"));
    }

    [Fact]
    public void BodyCap_IsWellAboveARealSignInButBounded()
    {
        Assert.InRange(LockoutMessageMiddleware.MaxCredentialBodyBytes, 8 * 1024, 1024 * 1024);
    }

    [Fact]
    public void PluginRoutedUsers_AreNotDoubleCountedForIpBans()
    {
        // TwoFactorAuthProvider records IP failures for these users itself.
        var routed = new User("sso", SignInProviderRestore.PluginProviderId, "reset");
        var plain = new User("plain", "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider", "reset");

        Assert.True(LockoutMessageMiddleware.IsPluginRoutedUser(routed));
        Assert.False(LockoutMessageMiddleware.IsPluginRoutedUser(plain));
        Assert.False(LockoutMessageMiddleware.IsPluginRoutedUser(null));
    }

    private sealed class AuthenticateUserByNameShape
    {
        public string? Username { get; set; }

        public string? Pw { get; set; }
    }
}
