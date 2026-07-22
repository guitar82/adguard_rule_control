"""Built-in rule presets for easier setup."""

from __future__ import annotations

from dataclasses import dataclass


PRESET_CUSTOM = "custom"


@dataclass(frozen=True)
class RulePreset:
    """A built-in rule preset."""

    key: str
    name: str
    icon: str
    rules: tuple[str, ...]


RULE_PRESETS: tuple[RulePreset, ...] = (
    RulePreset(
        key="youtube",
        name="Block YouTube",
        icon="mdi:youtube",
        rules=(
            "||youtube.com^",
            "||www.youtube.com^",
            "||m.youtube.com^",
            "||youtu.be^",
            "||youtube-nocookie.com^",
            "||googlevideo.com^",
            "||ytimg.com^",
        ),
    ),
    RulePreset(
        key="meta",
        name="Block Facebook and Instagram",
        icon="mdi:facebook",
        rules=(
            "||facebook.com^",
            "||www.facebook.com^",
            "||m.facebook.com^",
            "||fbcdn.net^",
            "||instagram.com^",
            "||www.instagram.com^",
            "||cdninstagram.com^",
            "||threads.net^",
        ),
    ),
    RulePreset(
        key="tiktok",
        name="Block TikTok",
        icon="mdi:music-note",
        rules=(
            "||tiktok.com^",
            "||www.tiktok.com^",
            "||m.tiktok.com^",
            "||tiktokcdn.com^",
            "||tiktokv.com^",
            "||byteoversea.com^",
            "||ibytedtos.com^",
        ),
    ),
    RulePreset(
        key="snapchat",
        name="Block Snapchat",
        icon="mdi:ghost",
        rules=(
            "||snapchat.com^",
            "||www.snapchat.com^",
            "||sc-cdn.net^",
            "||snapads.com^",
        ),
    ),
    RulePreset(
        key="discord",
        name="Block Discord",
        icon="mdi:controller-classic",
        rules=(
            "||discord.com^",
            "||discord.gg^",
            "||discordapp.com^",
            "||discordapp.net^",
            "||discordcdn.com^",
        ),
    ),
    RulePreset(
        key="reddit",
        name="Block Reddit",
        icon="mdi:reddit",
        rules=(
            "||reddit.com^",
            "||www.reddit.com^",
            "||old.reddit.com^",
            "||redd.it^",
            "||redditmedia.com^",
            "||redditstatic.com^",
        ),
    ),
    RulePreset(
        key="streaming",
        name="Block Streaming Apps",
        icon="mdi:television-play",
        rules=(
            "||netflix.com^",
            "||nflxvideo.net^",
            "||hulu.com^",
            "||disneyplus.com^",
            "||disney-plus.net^",
            "||max.com^",
            "||hbomax.com^",
            "||primevideo.com^",
            "||amazonvideo.com^",
            "||peacocktv.com^",
            "||paramountplus.com^",
            "||pluto.tv^",
            "||twitch.tv^",
            "||ttvnw.net^",
        ),
    ),
    RulePreset(
        key="gaming",
        name="Block Gaming Services",
        icon="mdi:gamepad-variant",
        rules=(
            "||steampowered.com^",
            "||steamcommunity.com^",
            "||steamstatic.com^",
            "||epicgames.com^",
            "||unrealengine.com^",
            "||xboxlive.com^",
            "||xbox.com^",
            "||playstation.net^",
            "||playstation.com^",
            "||nintendo.net^",
            "||nintendo.com^",
            "||roblox.com^",
            "||rbxcdn.com^",
            "||minecraft.net^",
        ),
    ),
    RulePreset(
        key="social",
        name="Block Social Media",
        icon="mdi:account-group",
        rules=(
            "||facebook.com^",
            "||instagram.com^",
            "||threads.net^",
            "||tiktok.com^",
            "||snapchat.com^",
            "||reddit.com^",
            "||x.com^",
            "||twitter.com^",
            "||pinterest.com^",
        ),
    ),
    RulePreset(
        key="custom_domain",
        name="Custom Domain Block",
        icon="mdi:web-off",
        rules=("||example.com^",),
    ),
)


def preset_choices() -> dict[str, str]:
    """Return choices for the options flow."""
    return {PRESET_CUSTOM: "Custom rules"} | {preset.key: preset.name for preset in RULE_PRESETS}


def get_preset(key: str) -> RulePreset | None:
    """Return a preset by key."""
    return next((preset for preset in RULE_PRESETS if preset.key == key), None)
