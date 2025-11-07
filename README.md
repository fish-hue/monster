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
git clone <your-repository-url> monster-tool
cd monster-tool

# Install Python dependencies (assuming you use a virtual environment)
pip install flask flask_cors requests uuid
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

1.  **Configure Target:**

      * Enter the **Target Origin** (e.g., `https://app.example.com`).
      * Enter the **Target Path** (e.g., `/api/protected`).
      * Define the **Cookie Name** and **Cookie Value** you wish to inject.

2.  **Perform a Basic Audit:**

      * Click **`Basic Cookie Injection Test`**.
      * The tool will:
          * Inject the specified cookie.
          * Execute a cross-origin `fetch()` request with `credentials: 'include'`.
          * Log the response status and all **CORS Headers** (`Access-Control-Allow-*`).
          * A successful request (e.g., status 200, 204) with the expected response body proves the vulnerability.

3.  **Test for CSRF:**

      * Change the **HTTP Method** (e.g., to `POST`).
      * Define a state-changing **Request Body** (e.g., a JSON payload for a `/transfer-funds` endpoint).
      * Click **`CSRF State-Change Test`**.
      * A successful low-status code (e.g., 200-202) response confirms that an attacker's domain can force a credentialed, state-changing request against the target.

4.  **Automate Evidence:**

      * Check the **`Auto-exfiltrate results to server`** checkbox.
      * Run any test. The Python server's `/collect-evidence` endpoint will receive the full result and save it to the `cookie_injection_evidence.jsonl` file.

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

**What's the next step you'd like to work on?** (e.g., Drafting the `requirements.txt` file, or expanding the "Usage Examples" section?)
