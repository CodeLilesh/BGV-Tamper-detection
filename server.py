"""
BGV Document Verification — Flask API Server
Serves the frontend and handles document verification through pipelines.
"""

import os
import sys
import json
import traceback
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipelines.aadhaar import verify_aadhaar
from pipelines.passport import verify_passport
from pipelines.tamper import detect_tampering
from pipelines.decision_engine import compute_verdict

app = Flask(__name__, static_folder='public', static_url_path='')

# Config
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --- Routes ---

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('public', path)


@app.route('/api/verify', methods=['POST'])
def verify_document():
    """Main verification endpoint."""
    try:
        # Check file
        if 'document' not in request.files:
            return jsonify({'error': 'No document file uploaded'}), 400

        file = request.files['document']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Allowed: PDF, JPG, PNG'}), 400

        doc_type = request.form.get('docType', 'other')
        password = request.form.get('password', '')
        candidate_name = request.form.get('candidateName', '')
        candidate_dob = request.form.get('candidateDob', '')

        # Save file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            # Route to correct pipeline
            pipeline_results = {}

            if doc_type == 'aadhaar':
                pipeline_results = verify_aadhaar(filepath, password)
            elif doc_type == 'passport':
                pipeline_results = verify_passport(filepath)
            else:
                pipeline_results = detect_tampering(filepath)

            # Decision Engine
            final_result = compute_verdict(pipeline_results, doc_type, candidate_name, candidate_dob)

            return jsonify(final_result)

        finally:
            # Clean up uploaded file
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except:
                    pass

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  BGV Document Verification Engine v2.1")
    print("  Server running at: http://localhost:5000")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)
