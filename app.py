# app.py

from flask import Flask, request, jsonify, render_template
import joblib
from feature_extraction import extract_all_features

app = Flask(__name__, template_folder='static', static_folder='static')

model = joblib.load("phishing_model.joblib")
feature_names = joblib.load("features.joblib")

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get("url")
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        features = extract_all_features(url)
        if not features:
            return jsonify({"error": "Feature extraction failed"}), 500

        input_vector = [features.get(name, 0) for name in feature_names]
        prediction = model.predict([input_vector])[0]
        confidence = model.predict_proba([input_vector])[0][1] * 100

        return jsonify({
            "url": url,
            "prediction": {
                "isPhishing": bool(prediction),
                "confidence": round(confidence, 2)
            },
            "features": features
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
