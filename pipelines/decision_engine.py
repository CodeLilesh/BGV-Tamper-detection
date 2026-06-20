"""
BGV Decision Engine
====================
Aggregates results from all pipelines and produces the final verdict.

Verdict outcomes:
  ✅ VERIFIED    — Document passed all checks
  ⚠️ SUSPICIOUS  — Some inconsistencies detected
  ❌ REJECTED    — Document failed critical checks

Confidence scoring:
  100 = perfect, 0 = completely unreliable
"""

import hashlib
import os
from datetime import datetime


def compute_verdict(pipeline_result, doc_type, candidate_name='', candidate_dob=''):
    """
    Main decision engine entry point.
    Takes pipeline results and produces the final verdict.
    """
    if 'error' in pipeline_result:
        return build_error_response(pipeline_result, doc_type)

    pipeline = pipeline_result.get('pipeline', doc_type)

    if pipeline == 'aadhaar':
        final_resp = compute_aadhaar_verdict(pipeline_result)
    elif pipeline == 'passport':
        final_resp = compute_passport_verdict(pipeline_result)
    else:
        final_resp = compute_tamper_verdict(pipeline_result)

    # Perform candidate cross-verification
    return cross_verify_candidate(final_resp, pipeline_result, candidate_name, candidate_dob)


def compute_aadhaar_verdict(result):
    """
    Aadhaar Decision Logic:
      signature_valid AND all_fields_match → ✅ VERIFIED
      signature_valid AND fields_mismatch → ⚠️ SUSPICIOUS
      signature_invalid                   → ❌ REJECTED
    """
    sig_valid = result.get('signature_valid')
    fields_match = result.get('fields_match')

    # Calculate confidence score
    confidence = 50  # Base

    checks = result.get('checks', [])
    passed_count = sum(1 for c in checks if c.get('passed'))
    total_count = len(checks) if checks else 1
    check_ratio = passed_count / total_count

    if sig_valid is True:
        confidence += 30
        if fields_match is True:
            verdict = 'VERIFIED'
            confidence += 20
            verdict_reason = 'PDF digital signature verified and all fields match'
        elif fields_match is False:
            verdict = 'SUSPICIOUS'
            confidence -= 10
            verdict_reason = 'PDF digital signature is valid but visible text does not match QR data — possible visual area tampering'
        else:
            # fields_match is None (couldn't compare)
            verdict = 'VERIFIED'
            confidence += 5
            verdict_reason = 'PDF digital signature verified. Field comparison was limited.'
    elif sig_valid is False:
        # User requested to bypass strict signature rejection and just verify fields
        if fields_match is True:
            verdict = 'VERIFIED'
            confidence = 85
            verdict_reason = 'PDF digital signature is invalid, but Name, DOB, and Gender match visible text perfectly'
        elif fields_match is None:
            verdict = 'SUSPICIOUS'
            confidence = max(40, int(check_ratio * 60))
            verdict_reason = 'PDF digital signature is invalid, and visible text could not be extracted for comparison'
        else:
            verdict = 'REJECTED'
            confidence = max(10, int(check_ratio * 30))
            verdict_reason = 'PDF digital signature is invalid AND fields do not match'
    else:
        # sig_valid is None (couldn't verify)
        # Fall back to check results
        if check_ratio >= 0.7:
            verdict = 'SUSPICIOUS'
            confidence = int(check_ratio * 60)
            verdict_reason = 'Signature verification inconclusive. Partial checks passed.'
        else:
            verdict = 'REJECTED'
            confidence = int(check_ratio * 40)
            verdict_reason = 'Could not verify document authenticity'

    confidence = min(max(confidence, 0), 100)

    return build_response(
        verdict=verdict,
        confidence=confidence,
        pipeline='aadhaar',
        checks=result.get('checks', []),
        flags=result.get('flags', []),
        verdict_reason=verdict_reason,
        extra={
            'qr_data_preview': {
                k: v for k, v in result.get('qr_data', {}).items()
                if k not in ('signature', 'signed_data', 'all_fields')
                and not isinstance(v, bytes)
            },
        }
    )


def compute_passport_verdict(result):
    """
    Passport Decision Logic:
      all_checksums_pass AND MRZ_matches_VIZ → ✅ VERIFIED
      checksum_fails                          → ❌ REJECTED
      checksum_pass BUT MRZ ≠ VIZ             → ⚠️ SUSPICIOUS
    """
    checksums_valid = result.get('checksums_valid')
    fields_match = result.get('fields_match')

    confidence = 50

    checks = result.get('checks', [])
    passed_count = sum(1 for c in checks if c.get('passed'))
    total_count = len(checks) if checks else 1

    if checksums_valid is True:
        confidence += 30
        if fields_match is True:
            verdict = 'VERIFIED'
            confidence += 20
            verdict_reason = 'All MRZ checksums valid and fields match visual zone'
        elif fields_match is False:
            verdict = 'SUSPICIOUS'
            confidence -= 10
            verdict_reason = 'MRZ checksums are valid but visual text does not match MRZ data — possible visual tampering'
        else:
            verdict = 'VERIFIED'
            confidence += 10
            verdict_reason = 'MRZ checksums verified. Visual comparison was limited.'
    elif checksums_valid is False:
        verdict = 'REJECTED'
        confidence = 15
        verdict_reason = 'MRZ checksum validation failed — document may be altered'
    else:
        verdict = 'SUSPICIOUS'
        confidence = 40
        verdict_reason = 'Could not fully validate MRZ checksums'

    confidence = min(max(confidence, 0), 100)

    # Include MRZ parsed data for display
    mrz_preview = {}
    mrz_data = result.get('mrz_data', {})
    for key in ['full_name', 'passport_number', 'nationality', 'dob_formatted',
                'gender_full', 'expiry_formatted', 'issuing_country']:
        if key in mrz_data:
            mrz_preview[key] = mrz_data[key]

    return build_response(
        verdict=verdict,
        confidence=confidence,
        pipeline='passport',
        checks=result.get('checks', []),
        flags=result.get('flags', []),
        verdict_reason=verdict_reason,
        extra={'mrz_data': mrz_preview}
    )


def compute_tamper_verdict(result):
    """
    Tamper Detection Decision Logic:
      tamper_score 0.00 – 0.30 → ✅ VERIFIED   (confidence ≥ 71)
      tamper_score 0.31 – 0.60 → ⚠️ SUSPICIOUS  (MEDIUM RISK)
      tamper_score 0.61 – 1.00 → ❌ REJECTED    (HIGH RISK)
      
      Additionally: if computed confidence < 71, verdict is clamped to SUSPICIOUS.
    """
    tamper_score = result.get('tamper_score', 0.0)

    if tamper_score <= 0.30:
        verdict = 'VERIFIED'
        confidence = int(100 - tamper_score * 100)
        risk_level = 'LOW'
        verdict_reason = f'Tamper score {tamper_score:.3f} (LOW RISK) — document appears authentic'
    elif tamper_score <= 0.60:
        verdict = 'SUSPICIOUS'
        confidence = int(70 - (tamper_score - 0.3) * 100)
        risk_level = 'MEDIUM'
        verdict_reason = f'Tamper score {tamper_score:.3f} (MEDIUM RISK) — anomalies detected, manual review recommended'
    else:
        verdict = 'REJECTED'
        confidence = int(40 - (tamper_score - 0.6) * 80)
        risk_level = 'HIGH'
        verdict_reason = f'Tamper score {tamper_score:.3f} (HIGH RISK) — significant tampering indicators found'

    confidence = min(max(confidence, 5), 100)

    # If confidence is below 71, escalate to SUSPICIOUS even if score looked clean
    if confidence < 71 and verdict == 'VERIFIED':
        verdict = 'SUSPICIOUS'
        risk_level = 'MEDIUM'
        verdict_reason = (
            f'Tamper score {tamper_score:.3f} — confidence {confidence}% is below threshold (71%). '
            'Manual review recommended.'
        )

    return build_response(
        verdict=verdict,
        confidence=confidence,
        pipeline='other',
        checks=result.get('checks', []),
        flags=result.get('flags', []),
        verdict_reason=verdict_reason,
        extra={
            'tamperScore': tamper_score,
            'riskLevel': risk_level,
            'moduleScores': result.get('module_scores', {}),
        }
    )


def build_response(verdict, confidence, pipeline, checks, flags, verdict_reason, extra=None):
    """Build the standardized verification response."""
    response = {
        'verdict': verdict,
        'confidenceScore': confidence,
        'verdictReason': verdict_reason,
        'pipeline': pipeline,
        'checks': sanitize_checks(checks),
        'flags': flags,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'engine': 'tamper-detection-v2.1',
    }

    if extra:
        response.update(extra)

    return response


def build_error_response(result, doc_type):
    """Build an error response when pipeline fails."""
    return {
        'verdict': 'REJECTED',
        'confidenceScore': 0,
        'verdictReason': result.get('error', 'Unknown error during verification'),
        'pipeline': doc_type,
        'checks': sanitize_checks(result.get('checks', [])),
        'flags': result.get('flags', []),
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'engine': 'tamper-detection-v2.1',
    }


def sanitize_checks(checks):
    """Ensure checks are JSON-serializable."""
    sanitized = []
    for check in checks:
        clean = {
            'name': str(check.get('name', '')),
            'passed': bool(check.get('passed', False)),
            'detail': str(check.get('detail', '')),
        }
        if check.get('warning'):
            clean['warning'] = True
        sanitized.append(clean)
    return sanitized


def cross_verify_candidate(final_resp, pipeline_result, expected_name, expected_dob):
    """Verify the extracted document data against the expected candidate details."""
    if not expected_name and not expected_dob:
        return final_resp

    doc_name = ''
    doc_dob = ''
    raw_text = ''
    
    # Extract name/dob/text based on the pipeline
    pipeline = final_resp.get('pipeline', '')
    if pipeline == 'aadhaar':
        qr_data = pipeline_result.get('qr_data', {})
        doc_name = qr_data.get('name', '')
        doc_dob = qr_data.get('dob', '')
        raw_text = pipeline_result.get('ocr_data', {}).get('text', '')
    elif pipeline == 'passport':
        mrz_data = pipeline_result.get('mrz_data', {})
        doc_name = mrz_data.get('full_name', '')
        doc_dob = mrz_data.get('dob_formatted', '')
        raw_text = pipeline_result.get('viz_data', {}).get('raw_text', '')
    else:
        raw_text = pipeline_result.get('raw_text', '')

    doc_name = doc_name.upper()
    expected_name = expected_name.strip().upper()
    expected_dob = expected_dob.strip()
    raw_text = raw_text.upper()

    penalties = 0

    if expected_name:
        passed = False
        if doc_name:
            # Check against explicitly extracted name
            expected_words = set(expected_name.split())
            doc_words = set(doc_name.split())
            common = expected_words & doc_words
            if len(common) >= min(len(expected_words), len(doc_words)) * 0.5:
                passed = True
        
        if not passed and raw_text:
            # Check raw text
            expected_words = [w for w in expected_name.split() if len(w) > 2]
            if expected_words:
                found_words = [w for w in expected_words if w in raw_text]
                if len(found_words) >= len(expected_words) * 0.5:
                    passed = True
        
        final_resp['checks'].insert(0, {
            'name': 'Candidate Name Cross-Check',
            'passed': passed,
            'detail': f'Expected: {expected_name} | Found on Doc: {"Yes" if passed else "No"}',
        })

        if not passed:
            penalties += 30
            final_resp['flags'].append({
                'module': 'IDENTITY',
                'severity': 'HIGH',
                'description': f"Document does not appear to belong to candidate '{expected_name}'",
            })

    if expected_dob:
        passed = False
        if doc_dob:
            # Check against extracted dob
            passed = expected_dob.replace('-', '') == doc_dob.replace('/', '').replace('-', '')
            
        if not passed and raw_text:
            # Look for YYYY or exact DOB in raw text
            parts = expected_dob.split('-')
            if len(parts) == 3:
                year = parts[0]
                if year in raw_text:
                    passed = True

        final_resp['checks'].insert(0, {
            'name': 'Candidate DOB Cross-Check',
            'passed': passed,
            'detail': f'Expected: {expected_dob} | Found on Doc: {"Yes" if passed else "No"}',
            'warning': True if not passed else False # Don't hard-fail DOB if not found perfectly
        })
        
        if not passed:
            penalties += 10
            final_resp['flags'].append({
                'module': 'IDENTITY',
                'severity': 'MEDIUM',
                'description': f"Expected DOB '{expected_dob}' not found perfectly on document",
            })

    # Apply penalties
    if penalties > 0:
        final_resp['confidenceScore'] = max(0, final_resp['confidenceScore'] - penalties)
        if penalties >= 30:
            final_resp['verdict'] = 'REJECTED'
            final_resp['verdictReason'] = 'Identity mismatch: The uploaded document does not belong to the candidate.'
        elif final_resp['verdict'] == 'VERIFIED':
            final_resp['verdict'] = 'SUSPICIOUS'
            final_resp['verdictReason'] = 'Identity mismatch detected during cross-verification.'

    return final_resp
