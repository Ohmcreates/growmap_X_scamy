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


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    print(f"[*] Starting Phishing URL Detection Flask server on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
