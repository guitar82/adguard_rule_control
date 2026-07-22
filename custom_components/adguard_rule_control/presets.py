"""Built-in rule presets for easier setup."""

from __future__ import annotations

from dataclasses import dataclass


PRESET_CUSTOM = "custom"
PRESET_BLOCK_WEBSITE = "block_website"


@dataclass(frozen=True)
class RulePreset:
    """A built-in rule preset."""

    key: str
    name: str
    description: str
    icon: str
    rules: tuple[str, ...]


RULE_PRESETS: tuple[RulePreset, ...] = (
    RulePreset(
        key="youtube",
        name="Block YouTube",
        description="Blocks YouTube website, app, thumbnails, and video delivery domains.",
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
        description="Blocks Facebook, Instagram, Threads, and common Meta media domains.",
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
        description="Blocks TikTok website, app, and common media delivery domains.",
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
        description="Blocks Snapchat website, app, and common media domains.",
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
        description="Blocks Discord chat, invite, app, and CDN domains.",
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
        description="Blocks Reddit website, short links, media, and static asset domains.",
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
        description="Blocks common video streaming services such as Netflix, Hulu, Disney+, Max, Prime Video, and Twitch.",
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
        description="Blocks common gaming services such as Steam, Epic, Xbox, PlayStation, Nintendo, Roblox, and Minecraft.",
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
        description="Blocks common social media services in one switch.",
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
        key="block_all",
        name="Block All Internet",
        description="Blocks all DNS lookups for the selected target. Best used only with one device/client.",
        icon="mdi:wifi-off",
        rules=("||*^",),
    ),
    RulePreset(
        key="adult",
        name="Block Adult Sites",
        description="A simple starter preset for adult-site domains. Use a full blocklist in AdGuard for stronger coverage.",
        icon="mdi:shield-alert",
        rules=(
            "||pornhub.com^",
            "||xvideos.com^",
            "||xnxx.com^",
            "||redtube.com^",
            "||youporn.com^",
            "||onlyfans.com^",
        ),
    ),
    RulePreset(
        key="custom_domain",
        name="Custom Domain Block",
        description="Starts with one example domain rule that you can edit.",
        icon="mdi:web-off",
        rules=("||example.com^",),
    ),
)


def preset_choices() -> dict[str, str]:
    """Return choices for the options flow."""
    choices = {
        PRESET_BLOCK_WEBSITE: "Block a website by name - easiest for one site",
        PRESET_CUSTOM: "Advanced custom rules",
    }
    choices.update({preset.key: f"{preset.name} - {preset.description}" for preset in RULE_PRESETS})
    return choices


def get_preset(key: str) -> RulePreset | None:
    """Return a preset by key."""
    return next((preset for preset in RULE_PRESETS if preset.key == key), None)
