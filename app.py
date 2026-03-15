from flask import Flask, render_template, request, jsonify
from phishing_detector import PhishingDetector

app = Flask(__name__)
detector = PhishingDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get('url', '')
    if not url:
        return jsonify({'error': 'URL не предоставлен'}), 400
    
    result = detector.predict_phishing(url)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
