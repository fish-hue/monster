# Monster: Enhanced Cookie Injection & CORS Misconfiguration PoC

**Monster** is a **professional-grade, ethical penetration testing tool** designed to demonstrate **critical CORS misconfigurations** — specifically the dangerous combination of:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

This allows **any third-party site** to make **credentialed requests** (cookies included) to your domain — **leaking sensitive data** and enabling **CSRF via CORS**.

Monster simulates a **real attacker-controlled site**, injects cookies, triggers requests, and **exfiltrates full evidence** to your server.

---

## Key Features

| Feature | Description |
|--------|-------------|
| **Multi-Vector Cookie Injection** | `standard`, `quoted`, `version`, `dummy` vectors to maximize injection success |
| **Direct CORS Test** | Raw `fetch(..., {credentials: 'include'})` to prove cookie leakage |
| **Server-Side Proxy Bypass** | Flask proxy (`/proxy-fetch`) completely bypasses browser CORS |
| **CSRF via CORS** | State-changing `POST`/`PUT`/`DELETE` with stolen cookies |
| **Timing Attack Analysis** | Detect auth vs unauth processing time differences |
| **Batch Endpoint Scanner** | Auto-probe 11 common API paths for leakage |
| **Investigator Notes** | Write, send, and log observations with timestamps |
| **Full Evidence Pipeline** | Auto-saved to `cookie_injection_evidence.jsonl` + `notes.log` |
| **Local Download & Clipboard** | Export full JSON evidence or copy logs |

---

## Ethical Use Only

> **This tool is for authorized security testing only.**

Use **only** on systems you own or have **explicit written permission** to test.

> **Do not use against any target without authorization.**

---

## Architecture

```
[Victim Site] ←(cookies)← [Monster HTML (attacker.com)] → [Flask + ngrok]
```

1. Victim is logged in on `https://target.com`
2. Opens `monster.html` in another tab
3. Monster injects session cookie via `document.cookie`
4. Makes `fetch(target, {credentials: 'include'})`
5. **Cookies are sent** due to misconfig
6. **Response + headers** exfiltrated to your server

---

## Setup (5 Minutes)

### 1. Start the Flask Server

```bash
git clone https://github.com/fish-hue/monster.git
cd monster
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install flask flask-cors requests
python exfil.py
python -m http.server 8081
ngrok start --all
```

> `exfil.py` Runs on `http://localhost:3000

### 2. Expose with ngrok

```bash
ngrok http start --all
```

Copy the **HTTPS** URLs (e.g., `https://abc123.ngrok.app port 3000`, `https://xyz789.ngrok.app port 5000`)

---

## Usage

### 1. Open `monster.html`

Open the ngrok port 5000 URL server in your browser, this will host `monster.html` put the ngrok port 3000 server URL in your browser to see test results in the `Exfiltration` page.

### 2. Configure

| Field | Example |
|------|--------|
| **Target Origin** | `https://portal.playground.example.com` |
| **Target Path** | `/api/protected` |
| **Cookie Name** | `session` |
| **Cookie Value** | `INJECTED` |
| **ngrok/Server URL** | `https://abc123.ngrok.io` |
| **Evidence endpoint** | `/collect-evidence` |

### 3. Test Connection

Click **"Test Server Connection"** → green check.

---

## Attack Modes

| Button | Purpose |
|-------|--------|
| **Basic Injection** | Quick test with one vector |
| **Multi-Vector Injection** | Try all injection tricks |
| **Direct CORS Test** | Raw credentialed fetch |
| **Use Server Proxy** | Full CORS bypass via Flask |
| **CSRF Test** | State-changing action |
| **Batch Scanner** | Scan common endpoints |
| **Timing Analysis** | Detect auth timing leaks |
| **Full Attack Chain** | Inject → Request → Exfiltrate |

---

## Evidence Collection

| File | Content |
|------|--------|
| `cookie_injection_evidence.jsonl` | Full attack results (JSONL) |
| `notes.log` | Investigator observations |
| Browser | **Download Evidence** or **Copy to Clipboard** |

---

## File Structure

```
monster/
├── claude.py                     # Flask exfiltration server
├── monster.html                  # Attack interface (fixed)
├── cookie_injection_evidence.jsonl
├── notes.log
└── README.md
```

---

## Sample Server Output

```text
EVIDENCE RECEIVED: cookie_injection_evidence
Target: https://portal.playground.example.com/api/protected
Success: True
Status: 200

NOTES RECEIVED
Target: https://portal.playground.example.com
Notes length: 342 chars
Notes:
2025-11-08 14:22: User logged in. Session cookie visible in request headers...
```

---

## Customization

### Change Exfiltration Path

Edit **Evidence endpoint** field in UI (default: `/collect-evidence`)

### Add Custom Endpoints

Edit `claude.py` to add new routes.

---

## License

**MIT License**

```text
Copyright (c) 2025 fish-hue \ The Underdog \ aka Knute

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

**Monster** – *Show them the monster in their CORS config.*

--- 

*Happy (ethical) hunting.*
