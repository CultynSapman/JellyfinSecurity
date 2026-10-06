using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Pins the Pushover message contract: field names Pushover expects, trimmed
/// credentials, and the documented 250/1024 character limits (Pushover rejects
/// longer values instead of truncating them).
/// </summary>
public class PushoverPayloadTests
{
    [Fact]
    public void Form_UsesPushoverFieldNames_AndTrimsCredentials()
    {
        var form = NotificationService.BuildPushoverForm("  app-token \n", " user-key ", "Title", "Body");

        Assert.Equal("app-token", form["token"]);
        Assert.Equal("user-key", form["user"]);
        Assert.Equal("Title", form["title"]);
        Assert.Equal("Body", form["message"]);
        Assert.Equal(4, form.Count);
    }

    [Fact]
    public void LongTitleAndMessage_AreClippedToPushoverLimits()
    {
        var form = NotificationService.BuildPushoverForm(
            "t", "u", new string('a', 400), new string('b', 5000));

        Assert.Equal(NotificationService.PushoverMaxTitle, form["title"].Length);
        Assert.Equal(NotificationService.PushoverMaxMessage, form["message"].Length);
        Assert.EndsWith("…", form["title"]);
        Assert.EndsWith("…", form["message"]);
    }

    [Fact]
    public void EmptyMessage_FallsBackToTitle()
    {
        // Pushover requires a non-empty message.
        var form = NotificationService.BuildPushoverForm("t", "u", "Account locked", "  ");
        Assert.Equal("Account locked", form["message"]);
    }

    [Fact]
    public void Endpoint_IsPushoverHttpsApi()
    {
        Assert.Equal("https://api.pushover.net/1/messages.json", NotificationService.PushoverApiUrl);
    }
}
