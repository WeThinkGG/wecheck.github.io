from flask import Flask, request, jsonify, render_template, redirect, url_for
import joblib
import numpy as np
import requests
import os
import hashlib
import time
import threading

app = Flask(__name__)

# Load AI model
model = joblib.load('malware_detection_model.pkl')  # Your AI model for malware detection

# API keys (Use environment variables for security)
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
HYBRID_ANALYSIS_API_KEY = os.getenv('HYBRID_ANALYSIS_API_KEY')
METADEFENDER_API_KEY = os.getenv('METADEFENDER_API_KEY')
JOTTI_API_URL = 'https://jotti.org/api'
CLEANMX_API_URL = 'https://cleanmx.org/api/'

# Feature extraction placeholder function
def extract_features(file):
    return np.random.rand(10)

# VirusTotal check
def check_with_virustotal(file_hash):
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    return response.json()

# Hybrid Analysis check
def check_with_hybrid_analysis(file):
    files = {'file': open(file, 'rb')}
    headers = {'api-key': HYBRID_ANALYSIS_API_KEY}
    response = requests.post('https://www.hybrid-analysis.com/api/v2/scan/file', headers=headers, files=files)
    return response.json()

# MetaDefender check
def check_with_metadefender(file):
    files = {'file': open(file, 'rb')}
    headers = {'apikey': METADEFENDER_API_KEY}
    response = requests.post('https://metadefender.opswat.com/v4/file', headers=headers, files=files)
    return response.json()

# Jotti check
def check_with_jotti(file):
    files = {'file': open(file, 'rb')}
    response = requests.post(JOTTI_API_URL, files=files)
    return response.json()

# CLEAN MX check
def check_with_cleanmx(file_hash):
    params = {'apikey': CLEANMX_API_URL, 'resource': file_hash}
    response = requests.get(f'{CLEANMX_API_URL}/file/{file_hash}', params=params)
    return response.json()

# Deletes a file after a delay (5 minutes)
def delete_file_after_delay(filename, delay):
    time.sleep(delay)
    if os.path.exists(filename):
        os.remove(filename)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    file.save(file.filename)

    # Calculate file hash (MD5)
    file_hash = hashlib.md5(open(file.filename, 'rb').read()).hexdigest()

    # API checks
    vt_result = check_with_virustotal(file_hash)
    ha_result = check_with_hybrid_analysis(file.filename)
    md_result = check_with_metadefender(file.filename)
    jotti_result = check_with_jotti(file.filename)
    cleanmx_result = check_with_cleanmx(file_hash)

    # AI-based prediction
    features = extract_features(file)
    prediction = model.predict([features])

    response = {
        'file_name': file.filename,
        'isMalicious': bool(prediction[0]),
        'virus_total': vt_result,
        'hybrid_analysis': ha_result,
        'metadefender': md_result,
        'jotti': jotti_result,
        'cleanmx': cleanmx_result
    }

    # Delete file after 5 minutes
    threading.Thread(target=delete_file_after_delay, args=(file.filename, 300)).start()

    if prediction[0]:  # Suspicious file
        return redirect(url_for('suspicious', result=response))
    else:
        return jsonify(response)

@app.route('/suspicious')
def suspicious():
    result = request.args.get('result', default='', type=str)
    return render_template('suspicious.html', result=result)

@app.route('/remove_suspicious_page')
def remove_suspicious_page():
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
