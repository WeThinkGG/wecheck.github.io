import logging
from flask import Flask, request, jsonify, render_template
import traceback

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/')
def index():
    return render_template('index.html')  # Render a simple index page with upload form

@app.route('/scan', methods=['POST'])
def scan_file():
    try:
        # Log the request data for debugging
        app.logger.debug('Received scan request with data: %s', request.form)

        # Check if a file is uploaded
        if 'file' not in request.files:
            raise ValueError("No file part in the request")
        
        file = request.files['file']

        if file.filename == '':
            raise ValueError("No selected file")
        
        # Here you would typically process the uploaded file for scanning.
        # For demonstration, we’ll just call a mock function.
        scan_result = get_scan_results(file.filename)  # Your method to get results
        
        # Log the scan result for debugging
        app.logger.debug('Scan result: %s', scan_result)

        # Ensure scan_result is structured correctly
        return render_template('scan_result.html', scans=scan_result['scans'])

    except Exception as e:
        app.logger.error('Error occurred while scanning file: %s', str(e))
        app.logger.debug(traceback.format_exc())  # Log the full traceback
        return render_template('error.html', error=str(e)), 500

def get_scan_results(file_name):
    # Simulated scan result with VirusTotal and Hybrid Analysis
    return {
        'scans': {
            'VirusTotal': {
                'detected': True,
                'result': {
                    'Malwarebytes': {'detected': True, 'result': 'Malware detected'},
                    'Avast': {'detected': False, 'result': None},
                    'Kaspersky': {'detected': False, 'result': None},
                    'Norton': {'detected': True, 'result': 'Threat found'},
                    'McAfee': {'detected': False, 'result': None},
                    'Bitdefender': {'detected': True, 'result': 'Suspicious activity detected'}
                }
            },
            'Hybrid Analysis': {
                'detected': True,
                'result': 'Suspicious behavior detected in the sample.'
            }
        }
    }

if __name__ == '__main__':
    app.run(debug=True)  # Enable Flask's debugger
