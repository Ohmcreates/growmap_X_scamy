import os
import uuid
import json
import secrets
import hashlib
import string
from datetime import datetime
from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd

from feature_extractor import extract_features, FEATURE_NAMES
from url_heuristics import inspect_url
from db import get_connection, init_db

app = Flask(__name__, template_folder='templates', static_folder='static')

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,X-Session-ID'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS,DELETE'
    return response

try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
_model = None

def get_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file '{MODEL_PATH}' not found.")
        _model = joblib.load(MODEL_PATH)
    return _model

def generate_session_id() -> str:
    # Generates a clean, compact 10-character cryptographically secure token
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(10))

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return f"{salt}${hashed}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    try:
        salt, hashed = stored_password.split('$', 1)
        test_hash = hashlib.sha256((salt + provided_password).encode('utf-8')).hexdigest()
        return secrets.compare_digest(hashed, test_hash)
    except Exception:
        return False

def get_authenticated_user():
    session_id = request.headers.get('X-Session-ID') or request.cookies.get('session_id')
    if not session_id:
        return None, None

    try:
        conn = get_connection()
    except Exception:
        return None, session_id

    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.session_id, s.user_id, u.email, u.name, s.created_at as session_created
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_id = %s AND s.is_active = TRUE
            """, (session_id,))
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE user_sessions SET last_active = NOW() WHERE session_id = %s", (session_id,))
                return row, session_id
    except Exception:
        return None, session_id
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return None, session_id

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/health', methods=['GET'])
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'Scam Spotter Full-Stack API',
        'model_loaded': os.path.exists(MODEL_PATH)
    })

@app.route('/api/auth/signup', methods=['POST', 'OPTIONS'])
def api_signup():
    if request.method == 'OPTIONS':
        return ('', 204)

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    name = (data.get('name') or '').strip()
    password = data.get('password') or ''

    if not email or '@' not in email:
        return jsonify({'error': 'Valid email address is required.'}), 400
    if len(name) < 2:
        return jsonify({'error': 'Full name must be at least 2 characters.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400

    try:
        conn = get_connection()
    except Exception as exc:
        return jsonify({'error': 'Database service currently unavailable. Please verify MySQL is running.'}), 503

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({'error': 'Account with this email already exists.'}), 409

            user_id = str(uuid.uuid4())
            pw_hash = hash_password(password)
            cur.execute(
                "INSERT INTO users (id, email, name, password_hash) VALUES (%s, %s, %s, %s)",
                (user_id, email, name, pw_hash)
            )

            session_id = generate_session_id()
            ip_addr = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')[:250]
            cur.execute(
                "INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent) VALUES (%s, %s, %s, %s)",
                (session_id, user_id, ip_addr, user_agent)
            )

            return jsonify({
                'message': 'Signup successful.',
                'sessionId': session_id,
                'user': {
                    'id': user_id,
                    'name': name,
                    'email': email
                }
            }), 201
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def api_login():
    if request.method == 'OPTIONS':
        return ('', 204)

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    try:
        conn = get_connection()
    except Exception as exc:
        return jsonify({'error': 'Database service currently unavailable. Please verify MySQL is running.'}), 503

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, email, name, password_hash FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            if not user:
                return jsonify({'error': 'No account found with this email. Please sign up first.'}), 404

            if not verify_password(user['password_hash'], password):
                return jsonify({'error': 'Invalid password. Please check your credentials.'}), 401

            session_id = generate_session_id()
            ip_addr = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')[:250]
            cur.execute(
                "INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent) VALUES (%s, %s, %s, %s)",
                (session_id, user['id'], ip_addr, user_agent)
            )

            return jsonify({
                'message': 'Login successful.',
                'sessionId': session_id,
                'user': {
                    'id': user['id'],
                    'name': user['name'],
                    'email': user['email']
                }
            })
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.route('/api/auth/me', methods=['GET', 'OPTIONS'])
def api_auth_me():
    if request.method == 'OPTIONS':
        return ('', 204)

    user, session_id = get_authenticated_user()
    if not user:
        return jsonify({'authenticated': False, 'user': None}), 200

    return jsonify({
        'authenticated': True,
        'sessionId': session_id,
        'user': {
            'id': user['user_id'],
            'name': user['name'],
            'email': user['email']
        }
    })

@app.route('/api/auth/logout', methods=['POST', 'OPTIONS'])
def api_logout():
    if request.method == 'OPTIONS':
        return ('', 204)

    session_id = request.headers.get('X-Session-ID')
    if session_id:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE user_sessions SET is_active = FALSE WHERE session_id = %s", (session_id,))
        finally:
            conn.close()

    return jsonify({'message': 'Logged out successfully.'})

@app.route('/api/scans', methods=['GET', 'POST', 'OPTIONS'])
def api_scans():
    if request.method == 'OPTIONS':
        return ('', 204)

    user, session_id = get_authenticated_user()

    # Strict Privacy & Security: Guests never store data to database and cannot fetch history
    if not user:
        if request.method == 'POST':
            return jsonify({'message': 'Guest mode: In-memory analysis only. No data stored.'}), 200
        return jsonify({'history': []}), 200

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        content_preview = (data.get('content') or '').strip()
        risk_score = int(data.get('riskScore', 0))
        risk_level = (data.get('riskLevel') or 'LOW').upper()
        scan_type = data.get('scanType', 'TEXT_MESSAGE')
        headline = data.get('headline', '')
        rules_fired = data.get('rulesFired') or []

        if not content_preview:
            return jsonify({'error': 'Scan content is required.'}), 400

        scan_id = str(uuid.uuid4())
        user_id = user['user_id']

        try:
            conn = get_connection()
        except Exception:
            return jsonify({'error': 'Database unavailable.'}), 503

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_records 
                    (id, user_id, session_id, scan_type, content_preview, risk_score, risk_level, headline, rules_fired_json)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    scan_id,
                    user_id,
                    session_id,
                    scan_type,
                    content_preview[:2000],
                    risk_score,
                    risk_level,
                    headline[:250],
                    json.dumps(rules_fired)
                ))
            return jsonify({
                'id': scan_id,
                'message': 'Scan record saved to database.',
                'createdAt': datetime.utcnow().isoformat()
            }), 201
        finally:
            try:
                conn.close()
            except Exception:
                pass

    if request.method == 'GET':
        user_id = user['user_id']
        try:
            conn = get_connection()
        except Exception:
            return jsonify({'history': []}), 200

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, scan_type, content_preview, risk_score, risk_level, headline, rules_fired_json, created_at
                    FROM scan_records
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                    LIMIT 100
                """, (user_id,))
                rows = cur.fetchall()
                for row in rows:
                    if row.get('created_at'):
                        row['created_at'] = row['created_at'].isoformat()
                    if isinstance(row.get('rules_fired_json'), str):
                        try:
                            row['rules_fired_json'] = json.loads(row['rules_fired_json'])
                        except Exception:
                            pass
                return jsonify({'history': rows})
        finally:
            try:
                conn.close()
            except Exception:
                pass

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        return ('', 204)

    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided.'}), 400

    heuristics = inspect_url(url)
    model = get_model()
    raw_feats = extract_features(url)
    df_feat = pd.DataFrame([raw_feats])[FEATURE_NAMES]

    probs = model.predict_proba(df_feat)[0]
    phish_prob = float(probs[1])
    is_phishing = phish_prob >= 0.50

    return jsonify({
        'url': url,
        'is_phishing': is_phishing,
        'confidence_score': round(phish_prob * 100, 2),
        'risk_level': 'HIGH' if phish_prob >= 0.60 else 'MEDIUM' if phish_prob >= 0.30 else 'LOW',
        'features': raw_feats,
        'heuristics': heuristics
    })

def _get_gemini_key():
    return os.environ.get('GEMINI_API_KEY') or os.environ.get('VITE_GEMINI_API_KEY') or ''

@app.route('/api/gemini/generate', methods=['POST', 'OPTIONS'])
def gemini_proxy():
    if request.method == 'OPTIONS':
        return ('', 204)

    import urllib.request

    data = request.get_json(silent=True) or {}
    payload = data.get('payload')
    target_model = data.get('targetModel', 'gemini-3.5-flash')

    if not payload:
        return jsonify({'error': 'Missing payload parameter.'}), 400

    api_key = _get_gemini_key()
    candidate_models = [target_model, 'gemini-3.8-flash']
    last_err = None

    for model in candidate_models:
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        try:
            req = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read().decode('utf-8')
                return jsonify({'data': json.loads(body), 'modelUsed': model})
        except urllib.error.HTTPError as err:
            err_body = err.read().decode('utf-8')
            last_err = f"HTTP {err.code}: {err_body}"
            if err.code in (404, 503):
                continue
            return jsonify({'error': last_err}), err.code
        except Exception as exc:
            last_err = str(exc)
            continue

    return jsonify({'error': last_err or 'All Gemini candidate models failed.'}), 502

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5001))
    print(f"[*] Starting Scam Spotter Full-Stack Backend on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
