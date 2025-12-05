from flask import Flask, render_template, request, jsonify
import json
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
    
    # ДОБАВЛЕНО: Проверка на ошибку валидации
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result)

@app.route('/batch_scan', methods=['POST'])
def batch_scan():
    urls = request.json.get('urls', [])
    if not urls:
        return jsonify({'error': 'Список URL не предоставлен'}), 400
    
    results = detector.batch_scan(urls)
    return jsonify({'results': results})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
