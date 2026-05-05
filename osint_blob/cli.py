"""
osint_blob.cli — interactive menu shown when the user runs `blob`.

Behavior:
  * Running `blob` with no args   -> interactive menu loop
  * Running `blob <string>`       -> one-shot classification (no menu)
  * Running `blob <string> --check` -> one-shot + HTTP verification
"""

import argparse
import sys

from .classifier import (
    HAVE_REQUESTS,
    attempt_decodes,
    classify,
    http_check,
    is_likely_hit,
    matching_rules,
)


BANNER = r"""
  _     _       _      ___  ____ ___ _   _ _____
 | |__ | | ___ | |__  / _ \/ ___|_ _| \ | |_   _|
 | '_ \| |/ _ \| '_ \| | | \___ \| ||  \| | | |
 | |_) | | (_) | |_) | |_| |___) | || |\  | | |
 |_.__/|_|\___/|_.__/ \___/|____/___|_| \_| |_|
        OSINT blob -> candidate URL classifier
"""


def print_decode_section(blob: str) -> None:
    decodes = attempt_decodes(blob)
    if decodes:
        print("Possible decodes (try these as the new blob if they look meaningful):")
        for method, text in decodes:
            preview = text if len(text) <= 80 else text[:77] + "..."
            print(f"  [{method:7}] {preview!r}")
    else:
        print("No clean decodes (base64/hex/base58/rot13).")
    print()


def print_shape_section(blob: str) -> None:
    shape = classify(blob)
    flags = []
    if shape.is_hex: flags.append("hex")
    if shape.is_alnum: flags.append("alnum")
    if shape.is_url_safe: flags.append("url-safe")
    if shape.is_lower_alnum: flags.append("lower-alnum")
    if shape.is_base58_charset: flags.append("base58-friendly")
    if shape.has_base64_padding: flags.append("has-b64-symbols")
    print(f"Length: {shape.length}   Charset flags: {', '.join(flags) or 'none'}")
    print()


def print_matches(blob: str, check: bool, timeout: float) -> None:
    rules = matching_rules(blob)
    if not rules:
        print("No service rules match this blob's shape.")
        print("Suggestions: try decoding it, or search the blob directly on Google/GitHub.")
        return

    print(f"Matching {len(rules)} service rule(s):\n")
    for rule in rules:
        print(f"-- {rule.service} --")
        print(f"   why: {rule.note}")
        for tmpl in rule.templates:
            url = tmpl.format(b=blob)
            if check:
                status, note = http_check(url, timeout)
                marker = " ✓" if is_likely_hit(status) else "  "
                status_str = str(status) if status is not None else "---"
                print(f"  {marker} [{status_str}] {url} {note}")
            else:
                print(f"     {url}")
        print()

    if check:
        print("Note: HTTP 200 doesn't always mean a real resource — many services serve")
        print("a 'not found' page with status 200. Eyeball the ones marked ✓.\n")


def classify_and_print(blob: str, check: bool = False, timeout: float = 4.0) -> None:
    print(f"\n=== Blob: {blob!r}  (length {len(blob)}) ===\n")
    print_decode_section(blob)
    print_shape_section(blob)
    print_matches(blob, check, timeout)


# =============================================================================
# Interactive menu
# =============================================================================

MENU = """\
  [1] Classify a blob (templates only, no network)
  [2] Classify + verify candidates over HTTP
  [3] Just decode a blob (base64 / hex / base58 / rot13)
  [4] About / supported services
  [5] Quit
"""


def supported_services() -> None:
    from .classifier import RULES
    print("\nSupported services:\n")
    for rule in RULES:
        print(f"  - {rule.service}: {rule.note}")
    print()


def prompt(text: str) -> str:
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def menu_loop() -> None:
    print(BANNER)
    if not HAVE_REQUESTS:
        print("(note: `requests` not installed — option [2] disabled. Run: pip install requests)\n")

    while True:
        print(MENU)
        choice = prompt("Choose an option [1-5]: ")
        print()

        if choice == "1":
            blob = prompt("Enter blob: ")
            if blob:
                classify_and_print(blob, check=False)
        elif choice == "2":
            if not HAVE_REQUESTS:
                print("Install requests first: pip install requests\n")
                continue
            blob = prompt("Enter blob: ")
            if not blob:
                continue
            timeout_str = prompt("HTTP timeout in seconds [4]: ") or "4"
            try:
                timeout = float(timeout_str)
            except ValueError:
                timeout = 4.0
            classify_and_print(blob, check=True, timeout=timeout)
        elif choice == "3":
            blob = prompt("Enter blob: ")
            if blob:
                print()
                print_decode_section(blob)
        elif choice == "4":
            supported_services()
        elif choice in ("5", "q", "quit", "exit"):
            print("Bye.")
            return
        else:
            print(f"Unknown option: {choice!r}\n")


# =============================================================================
# Entry point
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blob",
        description="Classify a mystery blob and suggest matching OSINT URL templates. "
                    "Run with no arguments for an interactive menu.",
    )
    parser.add_argument("blob", nargs="?", help="The blob/ID to classify (omit for menu).")
    parser.add_argument("--check", action="store_true",
                        help="Verify candidates with HTTP requests.")
    parser.add_argument("--timeout", type=float, default=4.0,
                        help="HTTP timeout in seconds (default 4).")
    args = parser.parse_args()

    if args.blob is None:
        menu_loop()
    else:
        classify_and_print(args.blob, check=args.check, timeout=args.timeout)


if __name__ == "__main__":
    main()
