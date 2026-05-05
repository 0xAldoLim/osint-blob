# osint-blob

A small CLI that takes a mystery string ("blob") — the kind that shows up in CTF / OSINT challenges — and tells you which web services it could plausibly be an ID for.

Instead of blindly trying every URL pattern, it **only suggests services whose ID format the blob actually fits**. A 32-character hex string won't be suggested for Pastebin (which uses 8 alphanumeric chars). A 6-character lowercase string won't be suggested for YouTube (which needs 11 url-safe chars). And so on.

## What it does

Given a blob, the tool:

1. Tries to **decode** it (Base64, hex, Base58, ROT13) in case the real blob is wrapped.
2. Classifies it by **length and charset** (hex / alnum / url-safe / lowercase / Base58-friendly / etc.).
3. Returns matching **URL templates** for services whose ID rules the blob satisfies.
4. Optionally **probes** each candidate URL over HTTP and flags likely hits.

## Supported services

| Category | Services |
|---|---|
| Paste | Pastebin, Rentry, Hastebin, GitHub Gist |
| Image | Imgur (image / album), ImgBB, Postimages, Lightshot (prnt.sc), Flickr |
| File | Catbox, Litterbox, Filebin, transfer.sh |
| Shortener | bit.ly, TinyURL, is.gd, v.gd, t.ly |
| Cloud | Google Drive, Google Docs/Sheets |
| Code/Video | YouTube, GitHub user, Git commit search, JSFiddle |
| Social | X / Twitter |
| Static hosting | GitHub Pages, Netlify, Vercel, Cloudflare Pages, Neocities |

## Install

### From source (recommended for now)

```bash
git clone https://github.com/0xAldoLim/osint-blob.git
cd osint-blob
pip install .
```

To enable the `--check` HTTP verification feature, install with the `check` extra:

```bash
pip install ".[check]"
```

This installs the `blob` command on your `PATH`.

## Usage

### Interactive menu

Just run `blob`:

```
$ blob

  _     _       _      ___  ____ ___ _   _ _____
 | |__ | | ___ | |__  / _ \/ ___|_ _| \ | |_   _|
 | '_ \| |/ _ \| '_ \| | | \___ \| ||  \| | | |
 | |_) | | (_) | |_) | |_| |___) | || |\  | | |
 |_.__/|_|\___/|_.__/ \___/|____/___|_| \_| |_|
        OSINT blob -> candidate URL classifier

  [1] Classify a blob (templates only, no network)
  [2] Classify + verify candidates over HTTP
  [3] Just decode a blob (base64 / hex / base58 / rot13)
  [4] About / supported services
  [5] Quit

Choose an option [1-5]:
```

### One-shot mode

```bash
blob dQw4w9WgXcQ                    # classify only
blob dQw4w9WgXcQ --check            # also probe each URL
blob dQw4w9WgXcQ --check --timeout 6
```

### Example output

```
$ blob aBcDeFgH

=== Blob: 'aBcDeFgH'  (length 8) ===

No clean decodes (base64/hex/base58/rot13).

Length: 8   Charset flags: alnum, url-safe, base58-friendly

Matching 12 service rule(s):

-- Pastebin --
   why: Pastebin paste keys are 8 alphanumeric chars.
     https://pastebin.com/aBcDeFgH
     https://pastebin.com/raw/aBcDeFgH

-- Rentry --
   why: Rentry slugs are 2-100 chars, [A-Za-z0-9_-].
     https://rentry.co/aBcDeFgH
     https://rentry.co/aBcDeFgH/raw

...
```

## How matches are filtered

Each service has a `fits(blob, shape) -> bool` predicate. A service only appears in the output if its predicate returns `True`. Examples of the rules baked in:

- Pastebin: exactly 8 alphanumeric chars
- Imgur: exactly 5 or 7 alphanumeric chars
- prnt.sc: exactly 6 lowercase alphanumeric chars
- YouTube: exactly 11 url-safe chars
- Flickr `flic.kr/p/`: 4–11 chars, Base58 charset (no `0/O/I/l`)
- GitHub username: 1–39 chars, alphanumeric + dashes, no leading/trailing dash
- X / Twitter username: 1–15 chars, `[A-Za-z0-9_]`
- Google Drive file ID: 25–44 chars, url-safe
- Catbox file: 6 lowercase alnum chars + extension (e.g. `ab12cd.png`)

If no rule matches, the tool tells you to try decoding the blob or searching it on Google/GitHub directly.

## Caveats

- **HTTP 200 is not always a hit.** Many services (Pastebin, etc.) serve a "not found" placeholder page with status 200. Treat the ✓ marker as "worth opening in a browser," not a confirmation.
- **Use only against blobs from challenges that are actually in scope.** Don't enumerate random IDs against real services. "I was doing OSINT" is not a legal shield.
- ID format rules change. If a service updates its slug format and this tool gets it wrong, file an issue or a PR with the updated rule.

## Project layout

```
osint-blob/
├── osint_blob/
│   ├── __init__.py
│   ├── classifier.py    # decoding, classification, rules, http_check
│   └── cli.py           # menu + argparse entry point
├── pyproject.toml       # registers the `blob` command
├── README.md
├── LICENSE
└── .gitignore
```

## Contributing

Add a new service by appending a `Rule(...)` to the `RULES` list in `osint_blob/classifier.py`. Each rule needs:

- `service`: display name
- `fits(blob, shape) -> bool`: a predicate that matches the service's actual ID format
- `templates`: list of URL patterns using `{b}` for the blob
- `note`: a one-line explanation of why this rule fits (shown in output)

## License

MIT — see [LICENSE](LICENSE).
