"""
BGV Document Verification — Flask API Server v3.0
Serves the frontend and handles document verification through pipelines.
New in v3.0: Digital fingerprinting + blockchain-style audit ledger anchoring.
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
from pipelines.fingerprint import compute_document_fingerprint, create_verification_record
from pipelines.blockchain_ledger import append_record, verify_chain_integrity, get_ledger_stats

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

            # ── v3.0: Digital Fingerprint + Blockchain Anchoring ────────
            fingerprint = {}
            ledger_block = {}
            try:
                fingerprint = compute_document_fingerprint(filepath, pipeline_results)
                candidate_id = f"CAND-{hash(candidate_name + candidate_dob) & 0xFFFFFF:06X}"
                verification_record = create_verification_record(
                    filepath=filepath,
                    doc_type=doc_type,
                    candidate_id=candidate_id,
                    fingerprint=fingerprint,
                    pipeline_result=pipeline_results,
                    verdict=final_result.get('verdict', 'UNKNOWN'),
                    confidence=final_result.get('confidence', 0),
                )
                ledger_block = append_record(verification_record)
                final_result['fingerprint'] = {
                    'crypto_hash': fingerprint.get('crypto_hash', ''),
                    'perceptual_hash': fingerprint.get('perceptual_hash', ''),
                    'composite_hash': fingerprint.get('composite_hash', ''),
                    'ledger_block': ledger_block.get('seq'),
                    'ledger_hash': ledger_block.get('block_hash', '')[:16] + '...',
                }
            except Exception as fp_err:
                print(f"[WARN] Fingerprinting/ledger error (non-fatal): {fp_err}")
                final_result['fingerprint'] = {'error': str(fp_err)}

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


@app.route('/api/ledger/verify', methods=['GET'])
def ledger_verify():
    """Verify the integrity of the entire blockchain audit ledger."""
    try:
        result = verify_chain_integrity()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ledger/stats', methods=['GET'])
def ledger_stats():
    """Get summary statistics of the audit ledger."""
    try:
        stats = get_ledger_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  BGV Document Verification Engine v3.0")
    print("  Fingerprinting + Blockchain Audit Ledger ENABLED")
    print("  Server running at: http://localhost:5000")
    print("=" * 60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)
