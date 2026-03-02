"""Username enumeration across social networks and online platforms.

Checks whether a username exists on each platform by inspecting the HTTP
response code / body returned for a profile URL.  All checks are executed
concurrently using a thread-pool to keep total run time manageable.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import NamedTuple

from osint_tool.models import FindingLevel, OsintResult
from osint_tool.modules.base import BaseModule
from osint_tool.utils.http import safe_get

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform registry
# Each entry describes how to probe a given platform.
# "error_type" can be "status_code" or "message" (inspect body text).
# ---------------------------------------------------------------------------

class PlatformSpec(NamedTuple):
    name: str
    url_template: str          # use {} as username placeholder
    error_type: str            # "status_code" | "message"
    error_code: int | None     # HTTP status that means "not found"
    error_message: str | None  # body substring that means "not found"
    category: str              # e.g. "social", "developer", "gaming"


PLATFORMS: list[PlatformSpec] = [
    # Social networks
    PlatformSpec("GitHub", "https://github.com/{}", "status_code", 404, None, "developer"),
    PlatformSpec("GitLab", "https://gitlab.com/{}", "status_code", 404, None, "developer"),
    PlatformSpec("Twitter/X", "https://x.com/{}", "status_code", 404, None, "social"),
    PlatformSpec("Instagram", "https://www.instagram.com/{}/", "status_code", 404, None, "social"),
    PlatformSpec("Reddit", "https://www.reddit.com/user/{}", "status_code", 404, None, "social"),
    PlatformSpec("LinkedIn", "https://www.linkedin.com/in/{}", "status_code", 999, None, "professional"),
    PlatformSpec("TikTok", "https://www.tiktok.com/@{}", "status_code", 404, None, "social"),
    PlatformSpec("Pinterest", "https://www.pinterest.com/{}/", "status_code", 404, None, "social"),
    PlatformSpec("Tumblr", "https://{}.tumblr.com/", "status_code", 404, None, "social"),
    PlatformSpec("Flickr", "https://www.flickr.com/people/{}/", "status_code", 404, None, "photo"),
    PlatformSpec("Medium", "https://medium.com/@{}", "status_code", 404, None, "blog"),
    PlatformSpec("Dev.to", "https://dev.to/{}", "status_code", 404, None, "developer"),
    PlatformSpec("Hashnode", "https://hashnode.com/@{}", "status_code", 404, None, "blog"),
    PlatformSpec("Twitch", "https://www.twitch.tv/{}", "status_code", 404, None, "gaming"),
    PlatformSpec("YouTube", "https://www.youtube.com/@{}", "status_code", 404, None, "social"),
    PlatformSpec("Vimeo", "https://vimeo.com/{}", "status_code", 404, None, "video"),
    PlatformSpec("SoundCloud", "https://soundcloud.com/{}", "status_code", 404, None, "music"),
    PlatformSpec("Spotify", "https://open.spotify.com/user/{}", "status_code", 404, None, "music"),
    PlatformSpec("Steam", "https://steamcommunity.com/id/{}", "message", None, "This ID is not found", "gaming"),
    PlatformSpec("Keybase", "https://keybase.io/{}", "status_code", 404, None, "security"),
    PlatformSpec("HackerNews", "https://news.ycombinator.com/user?id={}", "message", None, "No such user", "developer"),
    PlatformSpec("Product Hunt", "https://www.producthunt.com/@{}", "status_code", 404, None, "tech"),
    PlatformSpec("Kaggle", "https://www.kaggle.com/{}", "status_code", 404, None, "data"),
    PlatformSpec("DockerHub", "https://hub.docker.com/u/{}/", "status_code", 404, None, "developer"),
    PlatformSpec("NPM", "https://www.npmjs.com/~{}", "status_code", 404, None, "developer"),
    PlatformSpec("PyPI", "https://pypi.org/user/{}/", "status_code", 404, None, "developer"),
    PlatformSpec("Replit", "https://replit.com/@{}", "status_code", 404, None, "developer"),
    PlatformSpec("CodePen", "https://codepen.io/{}", "status_code", 404, None, "developer"),
    PlatformSpec("Bitbucket", "https://bitbucket.org/{}/", "status_code", 404, None, "developer"),
    PlatformSpec("StackOverflow", "https://stackoverflow.com/users/{}?tab=profile", "message", None, "Page Not Found", "developer"),
    PlatformSpec("Gravatar", "https://en.gravatar.com/{}", "status_code", 404, None, "social"),
    PlatformSpec("About.me", "https://about.me/{}", "status_code", 404, None, "social"),
    PlatformSpec("Angel.co", "https://angel.co/u/{}", "status_code", 404, None, "professional"),
    PlatformSpec("Patreon", "https://www.patreon.com/{}", "status_code", 404, None, "creator"),
    PlatformSpec("Ko-fi", "https://ko-fi.com/{}", "status_code", 404, None, "creator"),
    PlatformSpec("BuyMeACoffee", "https://buymeacoffee.com/{}", "status_code", 404, None, "creator"),
    PlatformSpec("Dribbble", "https://dribbble.com/{}", "status_code", 404, None, "design"),
    PlatformSpec("Behance", "https://www.behance.net/{}", "status_code", 404, None, "design"),
    PlatformSpec("500px", "https://500px.com/p/{}", "status_code", 404, None, "photo"),
    PlatformSpec("Unsplash", "https://unsplash.com/@{}", "status_code", 404, None, "photo"),
    PlatformSpec("Letterboxd", "https://letterboxd.com/{}/", "status_code", 404, None, "entertainment"),
    PlatformSpec("Goodreads", "https://www.goodreads.com/{}", "status_code", 404, None, "books"),
    PlatformSpec("Last.fm", "https://www.last.fm/user/{}", "status_code", 404, None, "music"),
    PlatformSpec("Bandcamp", "https://{}.bandcamp.com/", "status_code", 404, None, "music"),
    PlatformSpec("Mastodon (social.coop)", "https://social.coop/@{}", "status_code", 404, None, "social"),
    PlatformSpec("Lobste.rs", "https://lobste.rs/u/{}", "status_code", 404, None, "developer"),
    PlatformSpec("Itch.io", "https://{}.itch.io/", "status_code", 404, None, "gaming"),
    PlatformSpec("Wattpad", "https://www.wattpad.com/user/{}", "status_code", 404, None, "books"),
    PlatformSpec("Quora", "https://www.quora.com/profile/{}", "status_code", 404, None, "social"),
    PlatformSpec("Academia.edu", "https://independent.academia.edu/{}", "status_code", 404, None, "academic"),
    PlatformSpec("ResearchGate", "https://www.researchgate.net/profile/{}", "status_code", 404, None, "academic"),
]


class UsernameModule(BaseModule):
    """Check username existence across major online platforms."""

    name = "username"
    description = "Search a username across 50+ online platforms"
    supported_target_types = ["username"]

    def __init__(
        self,
        max_workers: int = 20,
        rate_limit: float = 10.0,
        timeout: int = 10,
        proxies: dict[str, str] | None = None,
    ) -> None:
        super().__init__(rate_limit=rate_limit, timeout=timeout, proxies=proxies)
        self._max_workers = max_workers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target: str) -> OsintResult:
        result = self._new_result(target)
        username = target.strip().lstrip("@")

        found: list[dict[str, str]] = []
        not_found: list[str] = []
        errors: list[str] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {
                executor.submit(self._check_platform, platform, username): platform
                for platform in PLATFORMS
            }
            for future in concurrent.futures.as_completed(futures):
                platform = futures[future]
                try:
                    status, url = future.result()
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{platform.name}: {exc}")
                    continue

                if status == "found":
                    found.append({"platform": platform.name, "url": url, "category": platform.category})
                else:
                    not_found.append(platform.name)

        # Sort for deterministic output
        found.sort(key=lambda x: x["platform"])
        not_found.sort()

        if found:
            result.add_finding(
                title=f"Username '{username}' found on {len(found)} platform(s)",
                description="\n".join(f"  • [{p['category']}] {p['platform']}: {p['url']}" for p in found),
                level=FindingLevel.HIGH,
                data={"found": found, "not_found": not_found},
            )
        else:
            result.add_finding(
                title=f"Username '{username}' not found on any checked platform",
                description=f"Checked {len(PLATFORMS)} platforms – no active profiles detected.",
                level=FindingLevel.INFO,
                data={"checked_platforms": len(PLATFORMS)},
            )

        result.errors.extend(errors)
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_platform(self, platform: PlatformSpec, username: str) -> tuple[str, str]:
        """Return ("found"|"not_found", profile_url)."""
        self._rate_limiter.wait()
        url = platform.url_template.format(username)
        response = safe_get(self.session, url, timeout=self.timeout, allow_redirects=True)

        if response is None:
            return "not_found", url

        if platform.error_type == "status_code":
            if response.status_code == platform.error_code:
                return "not_found", url
            if response.status_code < 400:
                return "found", url
            return "not_found", url

        # error_type == "message"
        if response.status_code >= 400:
            return "not_found", url
        if platform.error_message and platform.error_message.lower() in response.text.lower():
            return "not_found", url
        return "found", url
