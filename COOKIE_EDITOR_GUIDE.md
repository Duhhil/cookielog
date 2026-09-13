# Cookie-Editor Import Guide

This guide explains how to import captured session cookies into a browser using the
Cookie-Editor extension, then use them to take over the victim's authenticated sessions.

---

## Step 1: Install Cookie-Editor

Install the Cookie-Editor browser extension on the attacker's machine:

- **Firefox**: https://addons.mozilla.org/firefox/addon/cookie-editor/
- **Chrome/Edge/Brave/Vivaldi**: https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm

After installation, a cookie icon appears in the toolbar.

## Step 2: Get the session cookie file

After running cookielog, the session cookies are saved in:

```
loot/session_cookies.json
```

This file is in Cookie-Editor JSON format -- a JSON array of cookie objects like:

```json
[
  {
    "domain": ".github.com",
    "name": "_gh_sess",
    "value": "nPCFL6htaiE%2FpMUg5UipdW7g6Y1zqoQxVbthFhW...",
    "path": "/",
    "expirationDate": 0,
    "secure": true,
    "httpOnly": true,
    "sameSite": "Lax",
    "hostOnly": false,
    "session": true
  }
]
```

If you used `session_break.py` (Python extraction), the file is:

```
loot/session_decrypted.json
```

## Step 3: Import cookies

1. Open the browser where Cookie-Editor is installed
2. Navigate to the target site (e.g. `https://github.com`)
3. Click the Cookie-Editor icon in the toolbar
4. Click the **Import** button (bottom of the popup)
5. A text area appears -- open `loot/session_cookies.json` in a text editor
6. Select all (Ctrl+A), copy (Ctrl+C)
7. Paste into the Cookie-Editor import text area (Ctrl+V)
8. Click **Import** button

Cookie-Editor replaces all cookies for the current domain with the imported ones.

## Step 4: Reload and verify

1. Press **F5** or **Ctrl+R** to reload the page
2. You should now be logged in as the victim

### Important notes:

- **Navigate to the correct domain first.** Cookie-Editor only imports cookies for the
  current site's domain. If you import GitHub cookies while on `google.com`, they won't
  apply. Import cookies for each domain separately:
  - Go to `github.com` -> import cookies with domain `.github.com` or `github.com`
  - Go to `chatgpt.com` -> import cookies with domain `chatgpt.com` or `.chatgpt.com`
  - Go to `steamcommunity.com` -> import cookies with domain `steamcommunity.com`

- **Session cookies expire when the browser closes.** Session cookies (expirationDate=0)
  are not persisted to disk -- if you close the browser, they're gone. Keep the browser
  open until you're done.

- **Some sites use additional protections.** Sites like Google, GitHub, and Discord may
  validate the IP address, user-agent, or device fingerprint alongside the session cookie.
  If the session doesn't persist after reload:
  - Clear existing cookies for the domain first (Cookie-Editor -> Delete All)
  - Re-import the session cookies
  - Try matching the victim's user-agent (use a user-agent switcher extension)

## Step 5: Using `swap.py` for per-site import

If you only want cookies for one specific site, use `swap.py` to extract just that site's
cookies in Netscape format (which can also be imported via Cookie-Editor or used with curl):

```bat
:: List available sites
python swap.py

:: Extract GitHub cookies (Netscape format)
python swap.py github

:: Extract GitHub session cookies only
python swap.py github --session
```

This generates `swap\github.com.txt` in Netscape format.

To import a Netscape file in Cookie-Editor:
1. Open the `.txt` file, copy contents
2. In Cookie-Editor, click **Import**
3. Cookie-Editor auto-detects Netscape format and converts it

## Quick reference: which file to use

| File | Format | Use case |
|---|---|---|
| `loot/session_cookies.json` | Cookie-Editor JSON | Direct import for session cookies (browser hijack) |
| `loot/all_cookies.json` | Cookie-Editor JSON | All cookies including persistent ones |
| `loot/passwords.json` | Cookie-Editor JSON | Saved passwords (domain, username, value) |
| `loot/session_cookies.txt` | Netscape | Use with curl/wget or import in Cookie-Editor |
| `loot/all_cookies.txt` | Netscape | All cookies in Netscape format |
| `swap/<site>.txt` | Netscape | Per-site cookies for selective import |

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Imported but still not logged in | Wrong domain in browser when importing | Navigate to the target site URL first, then import |
| Session works briefly then logs out | Server IP/device fingerprint check | Use a VPN matching the victim's IP, or a user-agent switcher |
| Cookie-Editor says "invalid format" | File has extra whitespace or BOM | Open in a text editor, save as UTF-8 without BOM |
| Session cookie value is garbage/binary | Decryption failed (old build) | Rebuild with `build.bat` and re-run the payload |
| Some cookies have empty values | Cookie was set but never used by the browser | Normal -- some cookies are pre-allocated but empty |
