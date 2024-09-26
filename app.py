import os
import requests
from flask import Flask, request, render_template, jsonify

app = Flask(__name__)

# Replace with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    file_path = os.path.join('uploads', file.filename)
    file.save(file_path)

    # Scan the file with VirusTotal
    scan_result = scan_with_virustotal(file_path)
    
    # Clean up uploaded file after scanning
    os.remove(file_path)

    return render_template('scan_result.html', scans=scan_result)

def scan_with_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    
    # Upload the file for scanning
    with open(file_path, 'rb') as f:
        files = {'file': f}
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        response = requests.post(url, headers=headers, files=files)
    
    # Check if the upload was successful
    if response.status_code == 200:
        scan_id = response.json()['data']['id']
        return get_scan_report(scan_id)
    
    return {'VirusTotal': {'detected': False, 'result': {}}}

def get_scan_report(scan_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        scan_data = response.json()['data']
        results = {}
        for engine in scan_data['attributes']['last_analysis_results']:
            results[engine] = {
                'detected': scan_data['attributes']['last_analysis_results'][engine]['result'] is not None,
                'result': scan_data['attributes']['last_analysis_results'][engine]['result']
            }
        return {'VirusTotal': {'detected': True, 'result': results}}
    
    return {'VirusTotal': {'detected': False, 'result': {}}}

if __name__ == '__main__':
    app.run(debug=True)
