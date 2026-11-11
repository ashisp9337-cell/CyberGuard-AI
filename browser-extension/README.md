# CyberGuard AI - Safe Browsing (browser extension)

Warns you **before** a dangerous website opens, in every browser you use. It asks *your own* CyberGuard backend on
this computer (http://127.0.0.1:8000) about each page; nothing is sent to any other server unless you switch on
"threat lists" (then only site names go to VirusTotal, URLhaus and AbuseIPDB, using the keys in CyberGuard's settings).

| What it checks | How |
|---|---|
| Each page you open (look-alike, spoofed and manipulated addresses) | URL engine + models, without contacting the site |
| Redirects (a normal link that forwards you to a bad site) | every address on the way is judged |
| Fake login pages (only if you allow "check login pages") | the page's code, with your typing removed, goes to the fake-login-page model |
| Threat lists (only if you allow "threat lists", 11 Nov) | your CyberGuard asks VirusTotal, URLhaus and AbuseIPDB about the **site name only** (never the full address); results in the popup, a listed site gets the warning page |

Protection is **off until you switch it on** in the extension's settings. Private pages (this computer, your home or
office network, browser pages, files) are never sent.

## Install (one folder for every browser)

First start CyberGuard (backend + website), sign in, open **Settings -> Browser extension -> Connect a browser** and
copy the key (it is shown once).

**Chrome / Edge / Brave / Opera**
1. Open `chrome://extensions` (Edge: `edge://extensions`, Brave: `brave://extensions`, Opera: `opera://extensions`).
2. Switch on **Developer mode**.
3. Click **Load unpacked** and choose this `browser-extension` folder.
4. The settings page opens: paste the key, press **Connect**, then tick **Check each website I open**.
   (Optional) tick **Also check login pages** - the browser asks you to allow it.

**Firefox (128 or newer)**
1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...** and choose `manifest.json` in this folder.
3. Open the extension's settings (puzzle icon -> CyberGuard -> Settings), paste the key, **Connect**, switch on.
   Firefox removes temporary add-ons when it closes; a permanent install needs Mozilla signing.

## Turning it off
Press **Turn everything off** in the extension's settings, remove the extension, or delete its key in CyberGuard
Settings (that browser is disconnected at once).

## Tested (6 Nov 2026, real Chromium)
Off before permission: nothing checked. Normal site: opened. `paypa1-secure-login.com`: warning page. A normal link that
redirects to `sbi-kyc-update.top`: warning page. A fake login page on an ordinary-looking name: warning page (page
model). A genuine login page on the same name: opened normally. "Open it anyway": works and is remembered until the
browser closes. Firefox was not tested here (no Firefox in the test machine); the manifest uses the cross-browser format.
