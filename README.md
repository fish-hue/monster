-----

# 😈 Monster: Enhanced Cookie Injection Module

**Monster** is a powerful, multi-vector tool designed for **ethical cybersecurity testing** of **Cross-Origin Resource Sharing (CORS)** configurations, with a specific focus on **credentialed cross-origin requests** and **cookie injection vulnerabilities**.

It allows security researchers to simulate complex, multi-stage attacks from a client-side environment (HTML/JS) while utilizing a robust Python backend for proxying, evidence collection, and advanced server-side vulnerability checks (e.g., SSRF through Next.js CVE-2025-57822).

-----

## ✨ Key Features

  * **Multi-Vector Cookie Injection:** Tests standard, quoted, and versioned cookie injection mechanisms to maximize bypass potential.
  * **CORS Configuration Audit:** Directly tests for dangerous combinations of `Access-Control-Allow-Origin` (especially reflection or wildcard `*`) and `Access-Control-Allow-Credentials: true`.
  * **Targeted Attack Modes:**
      * **Basic/Advanced Injection:** Execute immediate CORS-with-credentials requests with injected cookies.
      * **CSRF State-Change Test:** Simulates state-changing operations (e.g., `POST`, `PUT`) to prove Cross-Site Request Forgery capability via CORS misconfiguration.
      * **Timing Attack Analysis:** Compares response times of authenticated (injected cookie) vs. unauthenticated requests to identify potential user/session enumeration flaws.
      * **Batch Endpoint Scanner:** Probes a list of common API endpoints for widespread vulnerability.
  * **Evidence Collection Pipeline:** Automatically logs all requests, responses, CORS headers, and timing data.
      * **Local Storage:** Saves results to the local Flask server (`cookie_injection_evidence.jsonl`).
      * **Automated Exfiltration:** Integrates with **n8n** webhooks for out-of-band evidence collection (e.g., SSRF callbacks).
  * **Integrated Server (Flask/Python):** Provides a robust local host with API endpoints for proxying, logging, and advanced SSRF/canary testing (e.g., Next.js CVE-2025-57822 probe).

-----

## ⚠️ Ethical Use Statement

**MONSTER IS A TOOL FOR ETHICAL CYBERSECURITY TESTING AND RESEARCH ONLY.**

This tool is designed to be used by **authorized security professionals** in **controlled, permissioned environments**. Do not use this software against any target without **explicit, written permission** from the asset owner. The author and contributors are not responsible for any misuse or damage caused by this program.

-----

## 🚀 Getting Started

### Prerequisites

1.  **Python 3.x**
2.  **Flask** and **requests** Python libraries.
3.  A modern web browser (for the HTML/JavaScript frontend).
4.  (Optional, for full functionality) An instance of **n8n** (a workflow automation tool) running and accessible to collect canary/SSRF evidence.

### 1\. Installation

Clone the repository and install the Python dependencies:

```bash
# Clone the repository
git clone https://github.com/fish-hue/monster.git
cd monster

# Install Python dependencies (assuming you use a virtual environment)
pip install flask flask_cors requests uuid

# Or you can try requirements.txt

# Install Python dependencies
pip install -r requirements.txt
```

### 2\. Configure the Backend (`app.py`)

Open `app.py` and update the following lines with your n8n production webhook URLs:

```python
# ============================================================================
# n8n CONFIGURATION - UPDATE THESE!
# ============================================================================
N8N_CANARY_WEBHOOK = "http://localhost:5678/webhook/your-canary-webhook-id"  # UPDATE THIS!
N8N_QUERY_WEBHOOK = "http://localhost:5678/webhook/your-query-webhook-id"    # UPDATE THIS!
```

> **Note:** The N8N endpoints are crucial for testing out-of-band vulnerabilities and exfiltrating evidence outside of the browser environment. If n8n is not used, the tool will fall back to in-memory logging and local file storage.

### 3\. Run the Server

Start the Flask application. By default, it runs on `http://0.0.0.0:5000`.

```bash
python app.py
```

### 4\. Access the Frontend

Access the main interface by pointing your browser to the local server, which hosts the `monster.html` file (aliased as `/`):

```
http://127.0.0.1:5000/
```

-----

## 🔬 Usage Examples

The **Monster** frontend is an interactive, single-page application (`monster.html`).

### 1\. **Configure Target:**

      * Enter the **Target Origin** (e.g., `https://app.example.com`).
      * Enter the **Target Path** (e.g., `/api/protected`).
      * Define the **Cookie Name** and **Cookie Value** you wish to inject

-----

### 2\. **Basic Credentialed CORS Test**

The primary function. This test quickly determines if the target endpoint is vulnerable to a simple CORS bypass allowing a cross-origin resource access with the user's browser-provided cookies.

  * **Goal:** Fetch data from `https://target.com/api/user-data` using an injected cookie.
  * **Method:** Set the **HTTP Method** to `GET`. Enter the injected **Cookie Name/Value**. Click **`Basic Cookie Injection Test`**.
  * **Successful Result:** The request receives a `200 OK` or similar status, and the response body contains protected data (e.g., JSON user profile). Crucially, the server logs will show a successful request originating from your attacker domain, proving the **CORS misconfiguration** (`Access-Control-Allow-Credentials: true` combined with a weak `Access-Control-Allow-Origin` policy).

-----

### 3\. **CSRF State-Change Test (Proof of Concept)**

This test moves from a read vulnerability (data exposure) to a write/state-change vulnerability (CSRF) by using a state-changing method (like `POST` or `PUT`) over the vulnerable CORS channel.

  * **Goal:** Force a state change (e.g., changing an email address or transferring funds) on the target.
  * **Method:**
    1.  Set the **HTTP Method** to a state-changing verb (e.g., `POST`, `PUT`, or `DELETE`).
    2.  Fill the **Request Body** with the necessary payload (e.g., `{"new_email": "attacker@mail.com"}`).
    3.  Enter the injected **Cookie Name/Value** (optional, but necessary to target specific authenticated features).
    4.  Click **`CSRF State-Change Test`**.
  * **Successful Result:** The request returns a status code indicating a successful operation (e.g., `200 OK`, `204 No Content`, or `302 Found`). This is a definitive **Proof of Concept** for CSRF via CORS misconfiguration.

-----

### 4\. **Timing Attack Analysis (Advanced)**

This method exploits the time difference between an authenticated request (using the injected cookie) and an unauthenticated request (without the cookie) to confirm if the cookie is being processed and, in some cases, to enumerate valid user IDs or session tokens.

  * **Goal:** Determine if the server-side logic is taking *significantly* longer to process a request when the injected cookie is **valid** compared to when it's **invalid** or **missing**.
  * **Method:**
    1.  Click **`Timing Attack Analysis`**.
    2.  Monster performs two requests to the target endpoint:
          * **Request A:** With the injected cookie.
          * **Request B:** Without the injected cookie.
    3.  The tool displays the time difference in milliseconds.
  * **Successful Result:** A clear, measurable time delta (e.g., **\>150ms difference**) between the two requests suggests the server is doing more work, likely a database lookup, for the authenticated request. This can confirm the **validity of an injected token** or identify if a **blind SQL injection** is possible via time-based techniques through the CORS channel.

-----

### 5\. **Automated Exfiltration and Canary Testing**

Monster uses its integrated Flask server to serve an advanced canary token/payload and provides endpoints for evidence exfiltration.

  * **Goal:** Capture evidence (like an SSRF callback or log data) to an external system (**n8n**) or store it locally.
  * **Setup:** Ensure your `app.py` is configured with your **n8n webhook URLs**.
  * **Method:**
    1.  Check the **`Auto-exfiltrate results to server`** checkbox in the frontend.
    2.  Run any test. The full response data (headers, body, timing) will be posted to the local Flask endpoint `/collect-evidence`, which then forwards it to your **n8n webhook** for permanent storage.
    3.  For **SSRF/Canary testing** (e.g., for Next.js CVE-2025-57822 or similar flaws): The Python server generates a unique payload (e.g., `http://127.0.0.1:5000/canary/[UNIQUE_ID]`). If the target is vulnerable, the server will log a hit to this endpoint (either locally or via n8n), confirming the vulnerability.
  * **Successful Result:**
      * The browser log confirms a successful post to the local server.
      * The `cookie_injection_evidence.jsonl` file on your local machine updates with the new log entry.
      * (If n8n is active) Your n8n workflow receives a webhook payload containing the full evidence.

-----

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file (if included in your repository) for full details.

```text
# Simplified MIT License

The MIT License (MIT)

Copyright (c) 2025 Fish-Hue aka Knute

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

-----
