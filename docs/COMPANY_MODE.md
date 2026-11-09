# CyberGuard for a company (10 Nov 2026)

One CyberGuard server protects the whole company. **Everyone** - the administrator (senior authority) and every
employee - signs in and uses **all** detection modules for their own protection, exactly as before. Company mode adds:

| | Who | What |
|---|---|---|
| **Employees** page | administrators | everyone who uses CyberGuard: online now / last seen, last IP + browser, sign-in method (Google / password), scans, threats, failed sign-ins, PCs; invite people; make / remove admin; disable / enable; sign out everywhere; each person's recent scans and sign-ins |
| **Devices** page | everyone | PCs that run the **CyberGuard Agent**: online / offline, last report, findings, open ports. Employees see their own PCs, administrators see every PC |
| **CyberGuard Agent** | each employee PC | reads security facts and sends them to the server, which judges them with the same engines as everything else |
| **Google sign-in** | everyone | "Sign in with Google" (same company rule as normal sign-up) |

Nothing that existed before was removed or changed in behaviour. On a server without the company settings below,
CyberGuard works exactly as before (anyone may sign up).

---

## 1. Who may join

Settings (cloud: `deploy/.env.cloud`; laptop: `backend\.env`):

| Setting | Meaning |
|---|---|
| `COMPANY_NAME` | shown on the sign-up page and to employees, e.g. `THREATORA Pvt Ltd` |
| `COMPANY_EMAIL_DOMAINS` | e.g. `threatora.in` (comma-separated). People with these e-mails join by themselves; **everyone else needs an invite** (Employees page > Invite). Empty = anyone may sign up |
| `ADMIN_EMAILS` | the owner(s): always administrator, can never be demoted or disabled from the web page |

Invites: the administrator enters an e-mail (e.g. a judge's Gmail) and chooses Employee or Administrator. The person
gets an e-mail with the sign-up link (if e-mail is set up) - the link is also shown on the page to share. An invite works
once and expires after 7 days (`INVITE_DAYS`). Google sign-in follows the same rule.

Disabling an account signs it out everywhere at once and stops its PCs' agents; nothing is deleted. Every
administrator action is written to the activity log.

## 2. Google sign-in (free, about 10 minutes)

1. https://console.cloud.google.com - sign in - create a project, e.g. `CyberGuard`.
2. Menu > **Google Auth Platform** > **Get started**: App name `CyberGuard`, your support e-mail, Audience
   **External**, contact e-mail > **Create**.
3. **Clients** > **Create client** > Application type **Web application**, name `CyberGuard web`.
   **Authorised JavaScript origins**: `https://<your CG_DOMAIN>` (the cloud link) and `http://localhost:5173` (laptop).
   No redirect URI is needed. **Create** - copy the **Client ID** (ends with `.apps.googleusercontent.com`).
   There is no secret to keep: the client ID is public by design.
4. **Audience**: while the app is "Testing", only the test users you list there can use Google sign-in. To let anyone
   (judges) use it, click **Publish app** (CyberGuard asks only for name, e-mail and picture - no Google review needed).
5. Put the client ID in:
   - cloud: `GOOGLE_CLIENT_ID=...` in `deploy/.env.cloud`, then the `up -d --build` command again;
   - laptop: `GOOGLE_CLIENT_ID=...` in `backend\.env` **and** `VITE_GOOGLE_CLIENT_ID=...` in the project's root `.env`,
     then restart the backend and `npm run demo`.

Without a client ID the Google button is simply not shown.

## 3. The CyberGuard Agent on an employee PC

What it reads (read-only - it never blocks, closes, deletes or changes anything; a notice says so when it starts):

| Part | What | How often | Needs |
|---|---|---|---|
| network | open ports and live connections (program, address, port) | 60 s | any system |
| logons | failed / successful Windows sign-ins of the last hour | 5 min | Windows, **Run as administrator** (skipped otherwise) |
| dns | website NAMES programs looked up - only names not sent in the last 7 days; the server keeps only dangerous ones | 60 s | Windows |
| downloads | NEW risky files in Downloads (programs, scripts, archives, disk images, macro documents, web pages, shortcuts, or any file that is really a program), up to 15 MB; documents, photos and videos are never sent | 30 s | any system |

It never reads the screen, keystrokes, messages, passwords or the contents of other files.

Install:
1. On the CyberGuard website: **Devices** > name the PC > **Create device key** (shown once). Administrators can make a
   key for any employee's PC.
2. On that PC: install Python 3 (python.org, tick "Add python.exe to PATH"), copy the project's `agent` folder to it,
   and in that folder run:
   ```
   python -m pip install psutil
   python cyberguard_agent.py --setup
   ```
   Enter the server address (shown on the Devices page, e.g. `https://<CG_DOMAIN>`) and paste the key.
3. Start it: `python cyberguard_agent.py` (keep the window open). For the Windows sign-in part open the terminal with
   right-click > **Run as administrator**. The PC shows as **online** on the Devices page within a minute.
   - `--once` = one round of every part, then stop (a quick test); `--dry-run` = show what would be sent, send nothing.
   - The key is kept in `agent_config.json` next to the agent (Git ignores it). Removing the PC on the Devices page
     stops the key at once.

On the demo laptop the agent can use the backend's Python:
`backend\venv\Scripts\python.exe agent\cyberguard_agent.py --setup`.

Findings from a PC appear in that employee's Scan History and alerts (tagged with the PC), on the Devices page
(employee + administrators) and in the employee's activity on the Employees page. Automatic-alert limits apply
(critical only by default, at most 5 an hour).

## 4. After updating the code: database

The company features add 2 database changes. On the laptop, once, in the `backend` folder:
```
venv\Scripts\python.exe -m alembic upgrade head
```
(The cloud server does this by itself at every start.) Without it the backend prints a DATABASE warning and sign-in
fails.
