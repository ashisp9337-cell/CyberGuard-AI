# CyberGuard on the internet: Azure for Students (9 Nov 2026)

One cloud server runs everything: the website, the API, PostgreSQL and the AI models. It is reached at one HTTPS
address, e.g. `https://cyberguard-ashis.centralindia.cloudapp.azure.com`. The laptop keeps running its own copy for the
live demo (watchers, browser extension) - nothing on the laptop changes.

```
visitor --HTTPS--> Caddy (website + certificate) --/api/*--> backend (production mode) --> PostgreSQL
                     ports 80/443 only                       internal                      internal
```

Tested in the workspace before this guide was written: production mode behind the same Caddy version over HTTPS -
sign-up with e-mail code, login with CAPTCHA (also after a wrong password), Secure / HttpOnly / SameSite login cookie,
security headers, hidden API docs, CORS, rate limits that a fake `X-Forwarded-For` cannot dodge, the live event
stream, scans, uploads deleted after the scan, logout. Also checked: the website builds from a clean copy exactly as
the server builds it, and the server installs exactly the package versions the 1,039 backend tests passed with. The two
Docker images themselves are built for the first time on the server (the workspace cannot download Docker images).

**Safety rules:** secrets go only into `deploy/.env.cloud` on the server (never into Git, never into chat).
The server never runs the laptop's watchers or the Telegram inbox (they belong to the laptop).

---

## A. On the laptop (10 minutes)

1. **Push the latest code to GitHub** (the server downloads it from there).
2. **Make an SSH key** (the "key" to log in to the server; no password can be guessed). In PowerShell:
   ```
   New-Item -ItemType Directory -Force $HOME\.ssh | Out-Null
   ssh-keygen -t ed25519 -f $HOME\.ssh\cyberguard_azure
   ```
   Press Enter for an empty passphrase (or type one and remember it). Then show the PUBLIC half - safe to copy:
   ```
   Get-Content $HOME\.ssh\cyberguard_azure.pub
   ```
   The file WITHOUT `.pub` is the private key: never share it.

## B. Create the server in Azure (15 minutes)

1. https://portal.azure.com -> **Create a resource** -> **Virtual machine** -> **Create**.
2. **Basics**
   - Subscription: **Azure for Students**. Resource group: **Create new** -> `cyberguard`.
   - Virtual machine name: `cyberguard`. Region: **(Asia Pacific) Central India** (if not allowed, any region it offers).
   - Image: **Ubuntu Server 24.04 LTS - x64 Gen2**.
   - Size: **Standard_B2ms** (2 vCPUs, 8 GiB memory) - "See all sizes" if it is not listed. If it is not offered,
     any size with **8 GiB** memory (e.g. D2as_v5, D2s_v5). Sizes with 4 GiB or less are too small for the AI models.
   - Authentication type: **SSH public key**. Username: `azureuser`. SSH public key source: **Use existing public
     key** -> paste the line from step A2.
   - Public inbound ports: **Allow selected ports** -> **SSH (22), HTTP (80), HTTPS (443)**.
3. **Disks**: OS disk type **Standard SSD**, size **64 GiB**.
4. **Review + create** -> **Create**. Wait for "Your deployment is complete" -> **Go to resource**.
5. **Give it a name**: on the VM's Overview click the **Public IP address** -> **Settings > Configuration** ->
   **DNS name label**: e.g. `cyberguard-ashis` -> **Save**. Your address is shown below it, e.g.
   `cyberguard-ashis.centralindia.cloudapp.azure.com`. This is `CG_DOMAIN`.
6. (Recommended) **SSH only from your computer**: VM -> **Networking** -> rule for port 22 -> Source **My IP address**
   -> Save. (Change it again if your internet address changes.)

## C. CAPTCHA keys - Cloudflare Turnstile (5 minutes, free)

Production mode requires a CAPTCHA for sign-up and login, so bots cannot create accounts or guess passwords.
1. https://dash.cloudflare.com (free account) -> **Turnstile** -> **Add widget**.
2. Name `CyberGuard`, **Hostname**: your `CG_DOMAIN` (without https://), Widget mode **Managed** -> **Create**.
3. Keep the page open: **Site key** (public) and **Secret key** (private) go into the settings in step E.

## D. Prepare the server (10 minutes)

In PowerShell on the laptop (use your own address):
```
ssh -i $HOME\.ssh\cyberguard_azure azureuser@cyberguard-ashis.centralindia.cloudapp.azure.com
```
Type `yes` the first time. Then, on the server:
```
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 docker-buildx git
git clone https://github.com/ashisp9337-cell/Cyberdeck-AI.git cyberguard
exit
```

**Upload the AI models** (about 2.3 GB, 30-60 minutes) - in PowerShell on the laptop:
```
cd C:\Users\ashis\Desktop\cyberguard-ai-fullstack\cyberguard-ai\backend\app\ml
scp -i $HOME\.ssh\cyberguard_azure -r models azureuser@cyberguard-ashis.centralindia.cloudapp.azure.com:~/
```
They land in `/home/azureuser/models` on the server.

## E. Settings on the server (10 minutes)

```
ssh -i $HOME\.ssh\cyberguard_azure azureuser@cyberguard-ashis.centralindia.cloudapp.azure.com
cd ~/cyberguard
cp deploy/cloud.env.example deploy/.env.cloud
chmod 600 deploy/.env.cloud
openssl rand -hex 32        # copy the output: JWT_SECRET
openssl rand -hex 24        # copy the output: POSTGRES_PASSWORD
nano deploy/.env.cloud
```
Fill in (Ctrl+O, Enter to save; Ctrl+X to close):

| Setting | Value |
|---|---|
| `CG_DOMAIN` | your address from B5 (no https://) |
| `CG_MODELS_DIR` | `/home/azureuser/models` |
| `POSTGRES_PASSWORD` | the `openssl rand -hex 24` output |
| `JWT_SECRET` | the `openssl rand -hex 32` output |
| `ADMIN_EMAILS` | your own e-mail: only this account gets the admin controls; everyone else who signs up is a normal user (the server refuses to start without it) |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` | from step C |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | the same values as in the laptop's `backend\.env` (Gmail App Password) |
| `GEMINI_API_KEY` | optional (without it the chat gives its backup answers) |
| `COMPANY_NAME`, `COMPANY_EMAIL_DOMAINS` | optional company mode: e.g. `THREATORA Pvt Ltd` and `threatora.in` - only those e-mails (and people you invite on the Employees page) can join; empty = anyone may sign up (see docs/COMPANY_MODE.md) |
| `GOOGLE_CLIENT_ID` | optional Google sign-in (docs/COMPANY_MODE.md, part 2); authorised JavaScript origin = `https://<CG_DOMAIN>` |
| `VIRUSTOTAL_API_KEY`, `URLHAUS_API_KEY`, `ABUSEIPDB_API_KEY` | optional: copy them from the laptop's `backend\.env` if they are set there, so links get the same live checks on the server |

## F. Start it (first time 15-25 minutes, later 1-2 minutes)

```
cd ~/cyberguard
sudo docker compose -f deploy/docker-compose.cloud.yml --env-file deploy/.env.cloud up -d --build
```
Watch the backend start (Ctrl+C stops watching, not the server):
```
sudo docker compose -f deploy/docker-compose.cloud.yml --env-file deploy/.env.cloud logs -f api
```
Ready when you see `Application startup complete` (production mode logs only warnings and errors after that, so a
quiet log is good). The AI models then load in the background for 1-2 minutes. Open `https://<CG_DOMAIN>` - the
padlock shows the free certificate Caddy got by itself. **Sign up with your ADMIN_EMAILS address.**

Check the models and the demo inputs on the server:
```
sudo docker compose -f deploy/docker-compose.cloud.yml --env-file deploy/.env.cloud exec api python demo_check.py
```
Sections 1 (model files 42/42), 2 (database), 4 (backend), 6 (demo inputs) and 11 (every model loads and runs: text,
links, sign-ins, e-mail, malware, network, insider, OCR, voice, speech-to-text, image, video) must say OK. Section 5
warns without a Gemini key; sections 7-10 warn because the demo files and the insider demo stay on the laptop.

## G. Later

| Task | Command (on the server, in `~/cyberguard`) |
|---|---|
| Update to the newest code | `git pull` then the `up -d --build` command from F |
| See what is running | `sudo docker compose -f deploy/docker-compose.cloud.yml --env-file deploy/.env.cloud ps` |
| Restart | `... restart` (same start of the command) |
| Stop paying after the final | Azure portal -> the VM -> **Stop** (status "Stopped (deallocated)"); **Start** brings it back with the same address |

Cost: a B2ms uses roughly 2 US dollars of the 100-dollar credit per day while it runs (check **Cost Management** in
the portal). Stopping it after the final keeps the credit.

## H. If something goes wrong

| What you see | Cause and fix |
|---|---|
| `required variable ... is missing a value` | a setting in `deploy/.env.cloud` is empty |
| The api container keeps restarting; log says `Unsafe production settings: ...` | production refuses unsafe settings; the message names them (e.g. JWT_SECRET too short) |
| Browser: site cannot be reached / certificate error | ports 80 and 443 must be open (B2); `CG_DOMAIN` must be exactly the DNS name; see `logs web` |
| "CAPTCHA verification failed" | the Turnstile widget's hostname must equal `CG_DOMAIN`; site and secret key not swapped |
| Sign-up code e-mail never arrives | SMTP values (Gmail App Password, not the normal password); production never prints codes |
| `models loaded` missing / scans say a model is missing | the upload in D did not finish: run the `scp` again |
| Out of memory | the VM must be B2ms (8 GiB) or bigger |
