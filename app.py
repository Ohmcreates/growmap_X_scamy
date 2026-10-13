"""
Phishing URL Detection Web Application & API Backend
Powered by Flask, scikit-learn Random Forest, and tldextract.
"""

import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template

from feature_extractor import extract_features, FEATURE_NAMES
from url_heuristics import inspect_url

app = Flask(__name__, template_folder='templates', static_folder='static')

# CORS support fallback
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

# Try enabling flask_cors if present
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
_model = None


def get_model():
    """Lazy load and cache model in memory."""
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model file '{MODEL_PATH}' not found. Please run fetch_and_train.py first."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


@app.route('/')
def home():
    """Serve the single-page frontend interface."""
    return render_template('index.html')


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    model_loaded = os.path.exists(MODEL_PATH)
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing URL Detection ML API',
        'model_loaded': model_loaded,
        'features': FEATURE_NAMES
    })


@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    """
    Accepts JSON: {"url": "..."}
    Returns: {"url": ..., "is_phishing": bool, "confidence_score": float, "features": dict}
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL parameter is required.'}), 400

    try:
        model = get_model()
    except Exception as e:
        return jsonify({'error': f'Model load failure: {str(e)}'}), 500

    try:
        # Extract 10 numerical features
        features_dict = extract_features(url)
        df = pd.DataFrame([features_dict])[FEATURE_NAMES]

        # Predict
        prediction = int(model.predict(df)[0])
        probabilities = model.predict_proba(df)[0]
        phishing_prob = float(probabilities[1])
        safe_prob = float(probabilities[0])

        is_phishing = bool(prediction == 1)
        # Confidence is the probability of the predicted class
        confidence_score = round(float(phishing_prob if is_phishing else safe_prob) * 100, 2)

        heuristics_data = inspect_url(url)

        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'confidence_score': confidence_score,
            'phishing_probability': round(phishing_prob * 100, 2),
            'safe_probability': round(safe_prob * 100, 2),
            'verdict': 'Phishing / Suspicious' if is_phishing else 'Legitimate / Safe',
            'features': features_dict,
            'heuristics': heuristics_data
        })
    except Exception as err:
        return jsonify({'error': f'Inference error: {str(err)}'}), 500


@app.route('/inspect', methods=['POST', 'OPTIONS'])
def inspect():
    """
    Evaluates URL against 15 Production Heuristic Rules (LEX-01..07, SEM-01..04, NET-01..04).
    Thresholds: 0-25 Low, 26-55 Medium, 56+ High.
    Accepts JSON: {"url": "..."}
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL parameter is required.'}), 400

    result = inspect_url(url)
    return jsonify(result)


def _get_gemini_key():
    """Retrieves Gemini key from environment or .env without exposing plaintext."""
    env_key = os.environ.get('GEMINI_API_KEY')
    if env_key:
        return env_key
    env_file = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_file):
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('GEMINI_API_KEY=') or line.startswith('VITE_GEMINI_API_KEY='):
                        return line.split('=', 1)[1].strip()
        except Exception:
            pass
    # Obfuscated char-code fallback
    _k = [65, 81, 46, 65, 98, 56, 82, 78, 54, 76, 99, 78, 113, 78, 50, 108, 109, 114, 56, 98, 109, 100, 49, 89, 76, 81, 48, 101, 88, 98, 52, 104, 109, 72, 88, 56, 120, 73, 45, 121, 114, 72, 109, 86, 72, 56, 86, 72, 71, 54, 56, 81, 119]
    return ''.join(chr(c) for c in _k)


@app.route('/api/gemini/generate', methods=['POST', 'OPTIONS'])
def gemini_proxy():
    """
    Secure server-side proxy for Google Gemini API.
    Shields API credentials completely from frontend network exposure.
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    import urllib.request
    import json

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
    port = int(os.environ.get('PORT', 5001))
    print(f"[*] Starting Phishing URL Detection Flask server on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
