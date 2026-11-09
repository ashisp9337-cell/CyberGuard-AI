CyberGuard Agent - reports this PC's security facts to the company's CyberGuard server
======================================================================================

It READS only (it never blocks, closes, deletes or changes anything):
  - open ports and live network connections            (every 60 s)
  - failed / successful Windows sign-ins (last hour)   (every 5 min, needs "Run as administrator")
  - website NAMES programs on this PC looked up        (every 60 s, Windows; dangerous ones are kept by the server)
  - NEW risky downloads (programs, scripts, archives, macro documents ...), max 15 MB  (every 30 s)
It never reads the screen, keystrokes, messages, passwords or other files.

1. On the CyberGuard website: Devices > name this PC > Create device key (shown once).
2. Here, in this folder:
       python -m pip install psutil
       python cyberguard_agent.py --setup      (server address + the key)
3. Start:
       python cyberguard_agent.py              (keep the window open; Ctrl+C stops)
   Quick test: python cyberguard_agent.py --once      Show without sending: --dry-run

agent_config.json (the key) and agent_state.json (what was already sent) stay on this PC; Git ignores them.
Full guide: docs/COMPANY_MODE.md
