from flask import Flask, request, jsonify, render_template
import requests
import os
import hashlib
import time
import threading

app = Flask(__name__)

# Assign API Keys directly (for development/testing purposes only)
VIRUSTOTAL_API_KEY = '12ffa54ff741d2df87e2f09074d91b6f69c514654e73d6b1eb29d8497f8b5fb0'
HYBRID_ANALYSIS_API_KEY = 'v051739qfe362472i4aj097h6f975483dqnqsiawab71a92d080vdmyua2f9066a'

# VirusTotal check
def check_with_virustotal(file_hash):
    try:
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_hash}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception("VirusTotal API failure")
    except Exception as e:
        print(f"VirusTotal failed: {e}")
        return None

# Fallback: Hybrid Analysis check
def check_with_hybrid_analysis(file):
    try:
        files = {'file': open(file, 'rb')}
        headers = {'api-key': HYBRID_ANALYSIS_API_KEY}
        response = requests.post('https://www.hybrid-analysis.com/api/v2/scan/file', headers=headers, files=files)
        return response.json()
    except Exception as e:
        print(f"Hybrid Analysis failed: {e}")
        return None

# Deletes a file after a delay (1 minute)
def delete_file_after_delay(filename, delay):
    time.sleep(delay)
    if os.path.exists(filename):
        os.remove(filename)
        print(f"File {filename} has been deleted from the system.")

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

    # First attempt to scan using VirusTotal
    vt_result = check_with_virustotal(file_hash)
    if vt_result:
        scan_result = {
            'scan_data': vt_result  # Direct report from VirusTotal
        }
    else:
        # If VirusTotal fails, use Hybrid Analysis as fallback
        ha_result = check_with_hybrid_analysis(file.filename)
        if ha_result:
            scan_result = {
                'scan_data': ha_result  # Direct report from Hybrid Analysis
            }
        else:
            return jsonify({'error': 'All scan services failed'}), 500

    # Message to indicate file will be deleted after 1 minute
    deletion_message = "This file will be deleted from our system after 1 minute."

    # Delete file after 1 minute (60 seconds)
    threading.Thread(target=delete_file_after_delay, args=(file.filename, 60)).start()

    return render_template('scan_result.html', result=scan_result, deletion_message=deletion_message)

if __name__ == '__main__':
    app.run(debug=True)
