"""
osint_blob.classifier — core blob classification + URL templating logic.
"""

import base64
import re
from dataclasses import dataclass
from typing import Callable, Optional

# ---- Optional dependency: requests (only needed for HTTP checks) ----
try:
    import requests  # type: ignore
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


# =============================================================================
# Decoding helpers
# =============================================================================

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def try_base64(s: str) -> Optional[str]:
    """Try standard and URL-safe base64. Pad as needed."""
    candidates = []
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded, validate=False)
            text = raw.decode("utf-8", errors="strict")
            if text and all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
                candidates.append(text)
        except Exception:
            continue
    return candidates[0] if candidates else None


def try_hex(s: str) -> Optional[str]:
    if len(s) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        raw = bytes.fromhex(s)
        text = raw.decode("utf-8", errors="strict")
        if text and all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
            return text
    except Exception:
        return None
    return None


def try_base58(s: str) -> Optional[str]:
    if not all(c in BASE58_ALPHABET for c in s):
        return None
    try:
        num = 0
        for c in s:
            num = num * 58 + BASE58_ALPHABET.index(c)
        out = bytearray()
        while num > 0:
            out.append(num & 0xFF)
            num >>= 8
        for c in s:
            if c == "1":
                out.append(0)
            else:
                break
        raw = bytes(reversed(out))
        text = raw.decode("utf-8", errors="strict")
        if text and all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
            return text
    except Exception:
        return None
    return None


def try_rot13(s: str) -> Optional[str]:
    """ROT13: only return if it would actually change the input."""
    rotated = s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))
    return rotated if rotated != s and any(c.isalpha() for c in s) else None


def attempt_decodes(blob: str) -> list[tuple[str, str]]:
    """Return [(method, decoded_text), ...] for any decode that succeeded."""
    results = []
    for name, fn in [
        ("base64", try_base64),
        ("hex", try_hex),
        ("base58", try_base58),
        ("rot13", try_rot13),
    ]:
        out = fn(blob)
        if out:
            results.append((name, out))
    return results


# =============================================================================
# Blob classification
# =============================================================================

@dataclass
class BlobShape:
    length: int
    is_hex: bool
    is_alnum: bool
    is_url_safe: bool
    is_lower_alnum: bool
    is_base58_charset: bool
    has_base64_padding: bool
    is_username_safe: bool
    is_github_user_safe: bool


def classify(blob: str) -> BlobShape:
    return BlobShape(
        length=len(blob),
        is_hex=bool(re.fullmatch(r"[0-9a-fA-F]+", blob)),
        is_alnum=bool(re.fullmatch(r"[A-Za-z0-9]+", blob)),
        is_url_safe=bool(re.fullmatch(r"[A-Za-z0-9_-]+", blob)),
        is_lower_alnum=bool(re.fullmatch(r"[a-z0-9]+", blob)),
        is_base58_charset=(
            bool(re.fullmatch(r"[A-Za-z0-9]+", blob))
            and not any(c in blob for c in "0OIl")
        ),
        has_base64_padding=any(c in blob for c in "=+/"),
        is_username_safe=bool(re.fullmatch(r"[A-Za-z0-9_]+", blob)),
        is_github_user_safe=bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", blob)),
    )


# =============================================================================
# Service rules
# =============================================================================

@dataclass
class Rule:
    service: str
    fits: Callable[[str, BlobShape], bool]
    templates: list[str]
    note: str


RULES: list[Rule] = [
    # --- Paste sites ---
    Rule(
        service="Pastebin",
        fits=lambda b, s: s.length == 8 and s.is_alnum,
        templates=[
            "https://pastebin.com/{b}",
            "https://pastebin.com/raw/{b}",
        ],
        note="Pastebin paste keys are 8 alphanumeric chars.",
    ),
    Rule(
        service="Rentry",
        fits=lambda b, s: 2 <= s.length <= 100 and s.is_url_safe,
        templates=[
            "https://rentry.co/{b}",
            "https://rentry.co/{b}/raw",
        ],
        note="Rentry slugs are 2-100 chars, [A-Za-z0-9_-].",
    ),
    Rule(
        service="Hastebin",
        fits=lambda b, s: 6 <= s.length <= 14 and s.is_lower_alnum,
        templates=[
            "https://hastebin.com/{b}",
            "https://hastebin.com/raw/{b}",
        ],
        note="Hastebin keys are short lowercase alphanumeric.",
    ),
    Rule(
        service="GitHub Gist",
        fits=lambda b, s: s.length == 32 and s.is_hex,
        templates=[
            "https://gist.github.com/{b}",
        ],
        note="Gist IDs are 32 hex chars (without username) or full SHA.",
    ),

    # --- Image hosts ---
    Rule(
        service="Imgur (image)",
        fits=lambda b, s: s.length in (5, 7) and s.is_alnum,
        templates=[
            "https://imgur.com/{b}",
            "https://i.imgur.com/{b}.png",
            "https://i.imgur.com/{b}.jpg",
        ],
        note="Imgur image IDs are 5 or 7 alphanumeric chars.",
    ),
    Rule(
        service="Imgur (album)",
        fits=lambda b, s: s.length in (5, 7) and s.is_alnum,
        templates=[
            "https://imgur.com/a/{b}",
            "https://imgur.com/gallery/{b}",
        ],
        note="Imgur album/gallery IDs are 5 or 7 alphanumeric chars.",
    ),
    Rule(
        service="ImgBB",
        fits=lambda b, s: s.length == 7 and s.is_alnum,
        templates=[
            "https://ibb.co/{b}",
        ],
        note="ImgBB short IDs are 7 alphanumeric chars.",
    ),
    Rule(
        service="Postimages",
        fits=lambda b, s: 6 <= s.length <= 10 and s.is_alnum,
        templates=[
            "https://postimg.cc/{b}",
        ],
        note="Postimages IDs are typically 6-10 alphanumeric chars.",
    ),
    Rule(
        service="Lightshot (prnt.sc)",
        fits=lambda b, s: s.length == 6 and s.is_lower_alnum,
        templates=[
            "https://prnt.sc/{b}",
        ],
        note="Lightshot screenshot IDs are 6 lowercase alphanumeric chars.",
    ),
    Rule(
        service="Flickr (short photo URL)",
        fits=lambda b, s: 4 <= s.length <= 11 and s.is_base58_charset,
        templates=[
            "https://flic.kr/p/{b}",
        ],
        note="Flickr short URLs use Base58 (no 0/O/I/l).",
    ),

    # --- File hosts ---
    Rule(
        service="Catbox",
        fits=lambda b, s: bool(re.fullmatch(r"[a-z0-9]{6}\.[a-z0-9]{2,4}", b)),
        templates=[
            "https://files.catbox.moe/{b}",
        ],
        note="Catbox files are 6 lowercase alphanumeric chars + extension (e.g. ab12cd.png).",
    ),
    Rule(
        service="Litterbox (catbox)",
        fits=lambda b, s: bool(re.fullmatch(r"[a-z0-9]{6,8}\.[a-z0-9]{2,4}", b)),
        templates=[
            "https://litter.catbox.moe/{b}",
        ],
        note="Litterbox uses 6-8 char filenames + extension.",
    ),
    Rule(
        service="Filebin",
        fits=lambda b, s: 8 <= s.length <= 32 and s.is_url_safe,
        templates=[
            "https://filebin.net/{b}",
        ],
        note="Filebin bin names are user-chosen, typically alphanumeric/dashes.",
    ),
    Rule(
        service="transfer.sh",
        fits=lambda b, s: 6 <= s.length <= 12 and s.is_alnum,
        templates=[
            "https://transfer.sh/{b}/file",
        ],
        note="transfer.sh path component is short alphanumeric (filename appended after).",
    ),

    # --- URL shorteners ---
    Rule(
        service="bit.ly",
        fits=lambda b, s: 4 <= s.length <= 30 and s.is_url_safe,
        templates=[
            "https://bit.ly/{b}",
        ],
        note="Bitly back-halves are 4-30 chars, [A-Za-z0-9_-].",
    ),
    Rule(
        service="TinyURL",
        fits=lambda b, s: 4 <= s.length <= 30 and s.is_url_safe,
        templates=[
            "https://tinyurl.com/{b}",
        ],
        note="TinyURL aliases are alphanumeric + dashes/underscores.",
    ),
    Rule(
        service="is.gd",
        fits=lambda b, s: 5 <= s.length <= 6 and s.is_alnum,
        templates=[
            "https://is.gd/{b}",
        ],
        note="is.gd codes are typically 5-6 alphanumeric chars.",
    ),
    Rule(
        service="v.gd",
        fits=lambda b, s: 5 <= s.length <= 6 and s.is_alnum,
        templates=[
            "https://v.gd/{b}",
        ],
        note="v.gd codes are typically 5-6 alphanumeric chars.",
    ),
    Rule(
        service="t.ly",
        fits=lambda b, s: 3 <= s.length <= 20 and s.is_url_safe,
        templates=[
            "https://t.ly/{b}",
        ],
        note="t.ly slugs are short, [A-Za-z0-9_-].",
    ),

    # --- Cloud / docs ---
    Rule(
        service="Google Drive (file)",
        fits=lambda b, s: 25 <= s.length <= 44 and s.is_url_safe,
        templates=[
            "https://drive.google.com/file/d/{b}/view",
        ],
        note="Google Drive file IDs are 25-44 chars, [A-Za-z0-9_-].",
    ),
    Rule(
        service="Google Docs",
        fits=lambda b, s: 25 <= s.length <= 60 and s.is_url_safe,
        templates=[
            "https://docs.google.com/document/d/{b}/edit",
            "https://docs.google.com/spreadsheets/d/{b}/edit",
        ],
        note="Google Docs/Sheets IDs are 25-60 chars, [A-Za-z0-9_-].",
    ),

    # --- Code / video ---
    Rule(
        service="YouTube",
        fits=lambda b, s: s.length == 11 and s.is_url_safe,
        templates=[
            "https://www.youtube.com/watch?v={b}",
            "https://youtu.be/{b}",
        ],
        note="YouTube video IDs are exactly 11 chars, [A-Za-z0-9_-].",
    ),
    Rule(
        service="Git commit (GitHub)",
        fits=lambda b, s: 7 <= s.length <= 40 and s.is_hex,
        templates=[
            "https://github.com/search?q={b}&type=commits",
        ],
        note="Git commit hashes are 7-40 hex chars. Without a repo, only searchable.",
    ),
    Rule(
        service="GitHub user",
        fits=lambda b, s: 1 <= s.length <= 39 and s.is_github_user_safe,
        templates=[
            "https://github.com/{b}",
            "https://api.github.com/users/{b}",
        ],
        note="GitHub usernames are 1-39 chars, alphanumeric + dashes, no leading/trailing dash.",
    ),
    Rule(
        service="X / Twitter user",
        fits=lambda b, s: 1 <= s.length <= 15 and s.is_username_safe,
        templates=[
            "https://x.com/{b}",
            "https://twitter.com/{b}",
        ],
        note="X/Twitter usernames are 1-15 chars, [A-Za-z0-9_].",
    ),
    Rule(
        service="JSFiddle",
        fits=lambda b, s: 4 <= s.length <= 10 and s.is_alnum,
        templates=[
            "https://jsfiddle.net/{b}/",
        ],
        note="JSFiddle slugs are short alphanumeric.",
    ),

    # --- Static hosting ---
    Rule(
        service="GitHub Pages / Netlify / Vercel",
        fits=lambda b, s: 1 <= s.length <= 63 and bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", b)),
        templates=[
            "https://{b}.github.io",
            "https://{b}.netlify.app",
            "https://{b}.vercel.app",
            "https://{b}.pages.dev",
            "https://{b}.neocities.org",
        ],
        note="Subdomain rules: lowercase alnum + dashes, no leading/trailing dash, max 63 chars.",
    ),
]


def matching_rules(blob: str) -> list[Rule]:
    """Return all rules whose fits() predicate accepts this blob."""
    shape = classify(blob)
    return [r for r in RULES if r.fits(blob, shape)]


# =============================================================================
# HTTP verification
# =============================================================================

def http_check(url: str, timeout: float = 4.0) -> tuple[Optional[int], str]:
    """Return (status_code, note). HEAD first, GET on 405/5xx."""
    if not HAVE_REQUESTS:
        return None, "(install `requests` to enable checks)"
    headers = {"User-Agent": "osint-blob-classifier/0.1"}
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers)
        if r.status_code == 405 or r.status_code >= 500:
            r = requests.get(url, allow_redirects=True, timeout=timeout, headers=headers, stream=True)
            r.close()
        final = r.url
        note = f"-> {final}" if final != url else ""
        return r.status_code, note
    except requests.exceptions.RequestException as e:
        return None, f"(error: {type(e).__name__})"


def is_likely_hit(status: Optional[int]) -> bool:
    return status in (200, 301, 302)
