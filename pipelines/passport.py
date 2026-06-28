"""
BGV Pipeline 2: Passport Verification
=======================================
Flow: PDF/Image → OCR MRZ Zone → Parse MRZ (ICAO 9303) → 
      Validate Check Digits → OCR VIZ (preprocessed) → Compare MRZ vs VIZ

MRZ (Machine Readable Zone) structure for Type 3 passport:
  Line 1: P<CCCFAMILYNAME<<GIVENNAMES<<<<<<<<<<<<<<<<<<<<
  Line 2: PPPPPPPPPCNNNDDDDDDCGEEEEEECOOOOOOOOOOOOOOC
  
Where:
  P = Passport number, C = Check digit, N = Nationality,
  D = DOB (YYMMDD), G = Gender, E = Expiry (YYMMDD), O = Optional

v3.0 Changes:
  - VIZ extraction now uses CLAHE + 2x upsampling + Otsu binarization
  - Tesseract PSM changed to auto-page (PSM 3) for VIZ, PSM 6 kept for MRZ
  - DOB patterns expanded to include DD-MMM-YYYY (e.g. 01 JAN 1990)
  - Improved name heuristics with passport-specific layout hints
"""

import os
import re
import traceback
from PIL import Image, ImageFilter, ImageEnhance
import numpy as np


# ICAO 9303 check digit weights
MRZ_WEIGHTS = [7, 3, 1]

# Character values for MRZ check digit computation
MRZ_CHAR_VALUES = {}
for i in range(10):
    MRZ_CHAR_VALUES[str(i)] = i
for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    MRZ_CHAR_VALUES[c] = i + 10
MRZ_CHAR_VALUES['<'] = 0


def verify_passport(filepath):
    """
    Main passport verification pipeline.
    Returns a dict with pipeline results for the decision engine.
    """
    result = {
        'pipeline': 'passport',
        'checks': [],
        'flags': [],
        'mrz_data': {},
        'viz_data': {},
        'checksums_valid': None,
        'fields_match': None,
    }

    # Step 1: Load image and text (if PDF)
    try:
        doc_data = load_document(filepath)
        image = doc_data['image']
        pdf_text = doc_data.get('text', '')
        
        result['checks'].append({
            'name': 'Document Loading',
            'passed': True,
            'detail': f'Document loaded ({image.width}x{image.height})' if image else 'Document text loaded',
        })
    except Exception as e:
        result['checks'].append({
            'name': 'Document Loading',
            'passed': False,
            'detail': f'Failed: {str(e)}',
        })
        result['error'] = f'Failed to load document: {str(e)}'
        return result

    # Step 2: Extract MRZ
    mrz_text = None
    
    # Try native text extraction first
    if pdf_text:
        mrz_text = extract_mrz_from_text(pdf_text)
        
    if not mrz_text and image:
        # Fallback to image cropping and OCR
        mrz_text = extract_mrz_from_image(image)

    if mrz_text:
        result['checks'].append({
            'name': 'MRZ Extraction',
            'passed': True,
            'detail': 'Machine Readable Zone detected',
        })
    else:
            result['checks'].append({
                'name': 'MRZ Extraction',
                'passed': False,
                'detail': 'No MRZ detected in document',
            })
            result['flags'].append({
                'module': 'MRZ',
                'severity': 'HIGH',
                'description': 'Could not detect Machine Readable Zone — cannot verify passport',
            })
            return result

    # Step 3: Parse MRZ
    parsed_mrz = parse_mrz(mrz_text)
    result['mrz_data'] = parsed_mrz

    if parsed_mrz.get('valid_structure'):
        result['checks'].append({
            'name': 'MRZ Structure',
            'passed': True,
            'detail': f'Type: {parsed_mrz.get("doc_type", "?")} | Issuer: {parsed_mrz.get("issuing_country", "?")}',
        })
    else:
        result['checks'].append({
            'name': 'MRZ Structure',
            'passed': False,
            'detail': 'MRZ format does not match ICAO 9303 standard',
        })

    # Step 4: Validate Check Digits
    checksum_results = validate_mrz_checksums(parsed_mrz)
    result['checksums_valid'] = checksum_results['all_valid']

    for check in checksum_results['checks']:
        result['checks'].append(check)

    if not checksum_results['all_valid']:
        result['flags'].append({
            'module': 'MRZ_CHECKSUM',
            'severity': 'HIGH',
            'description': 'MRZ check digit validation failed — possible document alteration',
        })

    # Step 5: Extract Visual Zone (VIZ)
    viz_data = {'name': None, 'dob': None, 'gender': None}
    
    if pdf_text:
        viz_data = extract_viz_from_text(pdf_text)
        
    if not viz_data.get('name') and not viz_data.get('dob') and image:
        viz_data_img = extract_viz_from_image(image)
        # Merge dicts, preferring non-None values from viz_data_img if viz_data is empty
        for k, v in viz_data_img.items():
            if not viz_data.get(k):
                viz_data[k] = v

    result['viz_data'] = viz_data

    if viz_data.get('name') or viz_data.get('dob'):
        result['checks'].append({
            'name': 'VIZ Text Extraction',
            'passed': True,
            'detail': 'Visual zone text extracted',
        })
    else:
        result['checks'].append({
            'name': 'VIZ Text Extraction',
            'passed': True,
            'warning': True,
            'detail': 'Limited VIZ text extracted — comparison may be partial',
        })

    # Step 6: Compare MRZ vs VIZ
    if parsed_mrz.get('valid_structure'):
        field_comparison = compare_mrz_viz(parsed_mrz, viz_data)
        result['fields_match'] = field_comparison['all_match']

        for check in field_comparison['checks']:
            result['checks'].append(check)

        if not field_comparison['all_match']:
            result['flags'].append({
                'module': 'MRZ_VIZ',
                'severity': 'MEDIUM',
                'description': 'Mismatch between MRZ data and visible text on passport',
            })

    return result


def load_document(filepath):
    """Load document as PIL Image and extract text if PDF."""
    ext = os.path.splitext(filepath)[1].lower()
    doc_data = {'image': None, 'text': ''}

    if ext == '.pdf':
        try:
            import fitz
            doc = fitz.open(filepath)
            
            # Extract text
            for page in doc:
                doc_data['text'] += page.get_text() + "\n"
            
            # Extract image (try to render the page at 2x)
            page = doc[0]
            mat = fitz.Matrix(2.0, 2.0)
            pix = page.get_pixmap(matrix=mat)
            doc_data['image'] = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
            doc.close()
            return doc_data
        except Exception as e:
            print(f"[WARN] fitz PDF load error: {e}")
            pass

    # Fallback for images
    try:
        doc_data['image'] = Image.open(filepath)
    except Exception as e:
        raise Exception(f"Could not load image: {e}")

    return doc_data


def extract_mrz_from_text(text):
    """Extract MRZ lines directly from raw text."""
    lines = text.strip().split('\n')
    mrz_lines = []

    for line in lines:
        line = line.strip().replace(' ', '')
        if len(line) >= 30:
            mrz_chars = sum(1 for c in line if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<')
            if mrz_chars / len(line) > 0.85:
                mrz_lines.append(line)

    if len(mrz_lines) >= 2:
        return '\n'.join(mrz_lines[-2:])
    return None


def extract_mrz_from_image(image):
    """
    Extract MRZ from passport image using image processing.
    MRZ is typically at the bottom of the passport page.
    """
    try:
        # Crop bottom 30% of image (where MRZ typically is)
        width, height = image.size
        bottom_crop = image.crop((0, int(height * 0.65), width, height))

        # Try OCR on the cropped region
        return ocr_mrz(bottom_crop)

    except Exception as e:
        print(f"[WARN] MRZ extraction error: {e}")
        return None


def ocr_mrz(image):
    """OCR the MRZ zone and extract the two MRZ lines."""
    text = ''

    try:
        # Try pytesseract
        try:
            import pytesseract
            text = pytesseract.image_to_string(
                image,
                config='--psm 6 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<'
            )
        except ImportError:
            pass

        # Try tesseract binary
        if not text:
            try:
                import subprocess
                import tempfile

                tmp_path = os.path.join(tempfile.gettempdir(), 'mrz_temp.png')
                image.save(tmp_path)

                proc = subprocess.run(
                    ['tesseract', tmp_path, 'stdout',
                     '--psm', '6',
                     '-c', 'tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<'],
                    capture_output=True, text=True, timeout=30
                )

                if proc.returncode == 0:
                    text = proc.stdout

                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

    except Exception:
        pass

    if not text:
        return None

    # Find MRZ lines (44 chars for passport, 36 for ID card)
    lines = text.strip().split('\n')
    mrz_lines = []

    for line in lines:
        line = line.strip().replace(' ', '')
        # MRZ line should be mostly uppercase letters, digits, and '<'
        if len(line) >= 30:
            mrz_chars = sum(1 for c in line if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<')
            if mrz_chars / len(line) > 0.85:
                mrz_lines.append(line)

    if len(mrz_lines) >= 2:
        # Return the last two valid MRZ lines
        return '\n'.join(mrz_lines[-2:])

    return None


def parse_mrz(mrz_text):
    """Parse MRZ text into structured fields per ICAO 9303."""
    result = {'valid_structure': False, 'raw': mrz_text}

    if not mrz_text:
        return result

    lines = mrz_text.strip().split('\n')
    lines = [l.strip() for l in lines if l.strip()]

    if len(lines) < 2:
        return result

    line1 = lines[-2] if len(lines) >= 2 else lines[0]
    line2 = lines[-1]

    # Pad lines to 44 characters
    line1 = line1.ljust(44, '<')[:44]
    line2 = line2.ljust(44, '<')[:44]

    result['line1'] = line1
    result['line2'] = line2

    # Parse Line 1
    doc_type = line1[0:2].replace('<', '')
    issuing_country = line1[2:5].replace('<', '')

    # Name parsing
    name_part = line1[5:]
    name_parts = name_part.split('<<')
    surname = name_parts[0].replace('<', ' ').strip() if name_parts else ''
    given_names = name_parts[1].replace('<', ' ').strip() if len(name_parts) > 1 else ''

    result['doc_type'] = doc_type
    result['issuing_country'] = issuing_country
    result['surname'] = surname
    result['given_names'] = given_names
    result['full_name'] = f'{given_names} {surname}'.strip()

    # Parse Line 2
    result['passport_number'] = line2[0:9].replace('<', '')
    result['passport_check'] = line2[9] if len(line2) > 9 else ''
    result['nationality'] = line2[10:13].replace('<', '') if len(line2) > 12 else ''
    result['dob'] = line2[13:19] if len(line2) > 18 else ''  # YYMMDD
    result['dob_check'] = line2[19] if len(line2) > 19 else ''
    result['gender'] = line2[20] if len(line2) > 20 else ''
    result['expiry'] = line2[21:27] if len(line2) > 26 else ''  # YYMMDD
    result['expiry_check'] = line2[27] if len(line2) > 27 else ''
    result['optional'] = line2[28:42] if len(line2) > 41 else ''
    result['optional_check'] = line2[42] if len(line2) > 42 else ''
    result['composite_check'] = line2[43] if len(line2) > 43 else ''

    # Format DOB for display
    if result['dob'] and len(result['dob']) == 6:
        yy, mm, dd = result['dob'][:2], result['dob'][2:4], result['dob'][4:6]
        year = int(yy)
        year = 1900 + year if year > 30 else 2000 + year
        result['dob_formatted'] = f'{dd}/{mm}/{year}'

    # Format expiry
    if result['expiry'] and len(result['expiry']) == 6:
        yy, mm, dd = result['expiry'][:2], result['expiry'][2:4], result['expiry'][4:6]
        year = int(yy)
        year = 1900 + year if year > 30 else 2000 + year
        result['expiry_formatted'] = f'{dd}/{mm}/{year}'

    # Gender mapping
    gender_map = {'M': 'MALE', 'F': 'FEMALE', '<': 'UNSPECIFIED'}
    result['gender_full'] = gender_map.get(result['gender'], result['gender'])

    result['valid_structure'] = True
    return result


def compute_mrz_check_digit(data_str):
    """Compute ICAO 9303 check digit for a data string."""
    total = 0
    for i, char in enumerate(data_str):
        value = MRZ_CHAR_VALUES.get(char.upper(), 0)
        weight = MRZ_WEIGHTS[i % 3]
        total += value * weight
    return total % 10


def validate_mrz_checksums(parsed_mrz):
    """Validate all MRZ check digits per ICAO 9303."""
    results = {'all_valid': True, 'checks': []}

    if not parsed_mrz.get('valid_structure'):
        results['all_valid'] = False
        results['checks'].append({
            'name': 'MRZ Checksum Validation',
            'passed': False,
            'detail': 'Cannot validate — invalid MRZ structure',
        })
        return results

    line2 = parsed_mrz.get('line2', '')
    if len(line2) < 44:
        results['all_valid'] = False
        return results

    # Check 1: Passport number check digit
    passport_data = line2[0:9]
    passport_check = line2[9]
    expected = compute_mrz_check_digit(passport_data)
    actual = int(passport_check) if passport_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'Passport Number Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
    })
    if not passed:
        results['all_valid'] = False

    # Check 2: DOB check digit
    dob_data = line2[13:19]
    dob_check = line2[19]
    expected = compute_mrz_check_digit(dob_data)
    actual = int(dob_check) if dob_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'DOB Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
    })
    if not passed:
        results['all_valid'] = False

    # Check 3: Expiry date check digit
    expiry_data = line2[21:27]
    expiry_check = line2[27]
    expected = compute_mrz_check_digit(expiry_data)
    actual = int(expiry_check) if expiry_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'Expiry Date Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
    })
    if not passed:
        results['all_valid'] = False

    # Check 4: Personal Number (Optional Data) Check Digit
    # ICAO 9303 specifies that if there is optional data, character 42 is its check digit
    optional_data = line2[28:42]
    optional_check = line2[42] if len(line2) > 42 else ''
    
    # Only validate if the optional check digit is not '<' and optional data exists
    if optional_check and optional_check != '<':
        expected = compute_mrz_check_digit(optional_data)
        actual = int(optional_check) if optional_check.isdigit() else -1
        passed = expected == actual
        results['checks'].append({
            'name': 'Personal Number Check Digit',
            'passed': passed,
            'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'Valid',
        })
        if not passed:
            results['all_valid'] = False

    # Check 5: Composite check digit
    # Composite = passport_number + check + DOB + check + expiry + check + optional + optional_check
    composite_data = line2[0:10] + line2[13:20] + line2[21:43]
    composite_check = line2[43]
    expected = compute_mrz_check_digit(composite_data)
    actual = int(composite_check) if composite_check.isdigit() else -1
    passed = expected == actual
    results['checks'].append({
        'name': 'Composite Check Digit',
        'passed': passed,
        'detail': f'Expected: {expected}, Got: {actual}' if not passed else 'All fields integrity verified',
    })
    if not passed:
        results['all_valid'] = False

    return results


def extract_viz_from_text(text):
    """
    Extract VIZ fields directly from native PDF text layer.
    v3.0: Expanded DOB patterns include DD-MMM-YYYY format.
    """
    result = {'name': None, 'dob': None, 'gender': None, 'raw_text': text}

    _SKIP_KEYWORDS = {
        'REPUBLIC', 'INDIA', 'PASSPORT', 'NATIONALITY', 'GIVEN',
        'SURNAME', 'NAMES', 'BIRTH', 'DATE', 'GENDER', 'PLACE',
        'EXPIRY', 'ISSUE', 'PERSONAL', 'NUMBER', 'SEX', 'FILE'
    }
    _MONTH_MAP = {
        'JAN': '01', 'FEB': '02', 'MAR': '03', 'APR': '04',
        'MAY': '05', 'JUN': '06', 'JUL': '07', 'AUG': '08',
        'SEP': '09', 'OCT': '10', 'NOV': '11', 'DEC': '12'
    }

    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # DOB — numeric formats (DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY)
        dob_match = re.search(r'(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})', line)
        if dob_match and not result['dob']:
            result['dob'] = dob_match.group(1).replace('-', '/').replace('.', '/')

        # DOB — textual format (DD MMM YYYY / DD-MMM-YYYY)
        if not result['dob']:
            dob_match2 = re.search(
                r'(\d{1,2})[\s\-]+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[\s\-]+(\d{4})',
                line, re.IGNORECASE
            )
            if dob_match2:
                dd = dob_match2.group(1).zfill(2)
                mm = _MONTH_MAP[dob_match2.group(2).upper()]
                yyyy = dob_match2.group(3)
                result['dob'] = f'{dd}/{mm}/{yyyy}'

        # Gender
        gender_match = re.search(r'\b(MALE|FEMALE)\b', line, re.IGNORECASE)
        if gender_match and not result['gender']:
            result['gender'] = gender_match.group(1).upper()

        # Name — mostly uppercase, no digits, not a label keyword
        if not result['name'] and 4 <= len(line) <= 50:
            upper_ratio = sum(1 for c in line if c.isupper()) / max(len(line), 1)
            words = set(line.upper().split())
            if upper_ratio > 0.65 and not any(c.isdigit() for c in line):
                if not words.intersection(_SKIP_KEYWORDS):
                    result['name'] = line

    return result


def _preprocess_for_ocr(image):
    """
    Preprocess an image region for high-accuracy Tesseract OCR.
    Pipeline: Grayscale → CLAHE contrast enhancement → 2× upsample → Otsu binarize
    """
    try:
        import cv2
        # Convert PIL → numpy
        img_np = np.array(image.convert('RGB'))
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)

        # CLAHE — Contrast Limited Adaptive Histogram Equalization
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        gray = clahe.apply(gray)

        # Upsample 2× for better glyph resolution (target ~300 DPI equivalent)
        h, w = gray.shape
        gray = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)

        # Otsu's binarization — adaptive threshold for mixed backgrounds
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

        # Mild denoising
        binary = cv2.medianBlur(binary, 3)

        # Convert back to PIL
        return Image.fromarray(binary)

    except ImportError:
        # Fallback: PIL-only enhancement without OpenCV
        img_gray = image.convert('L')
        # Sharpen + enhance contrast
        img_gray = ImageEnhance.Contrast(img_gray).enhance(2.0)
        img_gray = img_gray.filter(ImageFilter.SHARPEN)
        # Upsample 2×
        w, h = img_gray.size
        img_gray = img_gray.resize((w * 2, h * 2), Image.LANCZOS)
        return img_gray
    except Exception as e:
        print(f"[WARN] VIZ preprocessing fallback: {e}")
        return image


def extract_viz_from_image(image):
    """
    Extract text from the Visual Inspection Zone (upper portion of passport).

    v3.0: Applies CLAHE + 2× upsample + Otsu binarization before OCR.
    Uses Tesseract PSM 3 (automatic page segmentation) for the mixed VIZ layout.
    """
    result = {'name': None, 'dob': None, 'gender': None, 'raw_text': ''}

    try:
        # Crop top 65% of image (the Visual Inspection Zone)
        width, height = image.size
        top_crop = image.crop((0, 0, width, int(height * 0.65)))

        # ── Preprocess for OCR ────────────────────────────────────────
        preprocessed = _preprocess_for_ocr(top_crop)

        text = ''

        try:
            import pytesseract
            # PSM 3: Fully automatic page segmentation — best for VIZ area
            # (PSM 6 is for uniform text blocks like MRZ; VIZ has mixed layout)
            text = pytesseract.image_to_string(
                preprocessed,
                lang='eng',
                config='--psm 3 --oem 1'
            )
            # Fallback: try on original if preprocessed gives nothing
            if not text.strip():
                text = pytesseract.image_to_string(top_crop, lang='eng', config='--psm 3')
        except ImportError:
            try:
                import subprocess
                import tempfile

                tmp_path = os.path.join(tempfile.gettempdir(), 'viz_temp.png')
                preprocessed.save(tmp_path)
                proc = subprocess.run(
                    ['tesseract', tmp_path, 'stdout', '-l', 'eng', '--psm', '3'],
                    capture_output=True, text=True, timeout=30
                )
                if proc.returncode == 0:
                    text = proc.stdout
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

        if text:
            result['raw_text'] = text
            lines = text.strip().split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # ── DOB Patterns ─────────────────────────────────────────
                # DD/MM/YYYY or DD-MM-YYYY or DD.MM.YYYY
                dob_match = re.search(r'(\d{2}[/\-\.]\d{2}[/\-\.]\d{4})', line)
                if dob_match and not result['dob']:
                    result['dob'] = dob_match.group(1).replace('-', '/').replace('.', '/')

                # DD MMM YYYY (e.g. "01 JAN 1990" — common on Indian passports)
                if not result['dob']:
                    dob_match2 = re.search(
                        r'(\d{1,2})\s+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\s+(\d{4})',
                        line, re.IGNORECASE
                    )
                    if dob_match2:
                        month_map = {
                            'JAN': '01', 'FEB': '02', 'MAR': '03', 'APR': '04',
                            'MAY': '05', 'JUN': '06', 'JUL': '07', 'AUG': '08',
                            'SEP': '09', 'OCT': '10', 'NOV': '11', 'DEC': '12'
                        }
                        dd = dob_match2.group(1).zfill(2)
                        mm = month_map[dob_match2.group(2).upper()]
                        yyyy = dob_match2.group(3)
                        result['dob'] = f'{dd}/{mm}/{yyyy}'

                # ── Gender ───────────────────────────────────────────────
                gender_match = re.search(r'\b(MALE|FEMALE)\b', line, re.IGNORECASE)
                if gender_match and not result['gender']:
                    result['gender'] = gender_match.group(1).upper()

                # ── Name Heuristics ──────────────────────────────────────
                # Passport VIZ name: mostly uppercase, no digits, 4–50 chars,
                # not a known label keyword
                _SKIP_KEYWORDS = {
                    'REPUBLIC', 'INDIA', 'PASSPORT', 'NATIONALITY', 'GIVEN',
                    'SURNAME', 'NAMES', 'BIRTH', 'DATE', 'GENDER', 'PLACE',
                    'EXPIRY', 'ISSUE', 'PERSONAL', 'NUMBER', 'SEX', 'FILE'
                }
                if not result['name'] and 4 <= len(line) <= 50:
                    upper_ratio = sum(1 for c in line if c.isupper()) / max(len(line), 1)
                    words = set(line.upper().split())
                    if upper_ratio > 0.65 and not any(c.isdigit() for c in line):
                        if not words.intersection(_SKIP_KEYWORDS):
                            result['name'] = line

    except Exception as e:
        print(f"[WARN] VIZ extraction error: {e}")

    return result


def compare_mrz_viz(mrz_data, viz_data):
    """Compare MRZ fields with VIZ (visual zone) fields."""
    comparison = {'all_match': True, 'checks': []}

    viz_raw_text = (viz_data.get('raw_text') or '').upper()

    # Compare Name
    mrz_name = mrz_data.get('full_name', '').strip().upper()
    viz_name = (viz_data.get('name') or '').strip().upper()

    match = False
    used_viz_name = viz_name if viz_name else "Not found"

    if mrz_name:
        # First try strict word match against the extracted viz_name
        name_words_mrz = set(mrz_name.split())
        if viz_name:
            name_words_viz = set(viz_name.split())
            common = name_words_mrz & name_words_viz
            if len(common) >= min(len(name_words_mrz), len(name_words_viz)) * 0.5:
                match = True
        
        # If no match yet, search for the MRZ name in the raw text
        if not match and viz_raw_text:
            mrz_words = [w for w in mrz_name.split() if len(w) > 2]
            if mrz_words:
                found_words = [w for w in mrz_words if w in viz_raw_text]
                if len(found_words) >= len(mrz_words) * 0.5:
                    match = True
                    used_viz_name = " ".join(found_words) + " (Found in document text)"
                else:
                    used_viz_name = viz_name if viz_name else "Not found in document text"

        comparison['checks'].append({
            'name': 'Name Match (MRZ vs VIZ)',
            'passed': match,
            'detail': f'MRZ: {mrz_data.get("full_name", "N/A")} | VIZ: {used_viz_name}',
        })
        if not match:
            comparison['all_match'] = False
    else:
        comparison['checks'].append({
            'name': 'Name Match (MRZ vs VIZ)',
            'passed': True,
            'warning': True,
            'detail': 'MRZ name not parsed — comparison skipped',
        })

    # Compare DOB
    mrz_dob = mrz_data.get('dob_formatted', '')
    viz_dob = (viz_data.get('dob') or '').replace('-', '/').replace('.', '/')

    if mrz_dob and viz_dob:
        dob_match = mrz_dob == viz_dob
        comparison['checks'].append({
            'name': 'DOB Match (MRZ vs VIZ)',
            'passed': dob_match,
            'detail': f'MRZ: {mrz_dob} | VIZ: {viz_dob}',
        })
        if not dob_match:
            comparison['all_match'] = False
    else:
        comparison['checks'].append({
            'name': 'DOB Match (MRZ vs VIZ)',
            'passed': True,
            'warning': True,
            'detail': 'VIZ DOB not extracted — comparison skipped',
        })

    # Compare Gender
    mrz_gender = mrz_data.get('gender_full', '').strip().upper()
    viz_gender = (viz_data.get('gender') or '').strip().upper()
    
    if not viz_gender and viz_raw_text:
        if re.search(r'\b(MALE|FEMALE)\b', viz_raw_text, re.IGNORECASE):
            viz_gender = re.search(r'\b(MALE|FEMALE)\b', viz_raw_text, re.IGNORECASE).group(1).upper()

    if mrz_gender and mrz_gender != 'UNSPECIFIED':
        if viz_gender:
            gender_match = mrz_gender == viz_gender
            comparison['checks'].append({
                'name': 'Gender Match (MRZ vs VIZ)',
                'passed': gender_match,
                'detail': f'MRZ: {mrz_gender} | VIZ: {viz_gender}',
            })
            if not gender_match:
                comparison['all_match'] = False
        else:
            comparison['checks'].append({
                'name': 'Gender Match (MRZ vs VIZ)',
                'passed': True,
                'warning': True,
                'detail': 'VIZ Gender not extracted — comparison skipped',
            })

    # Compare Nationality
    mrz_nationality = mrz_data.get('nationality', '').strip().upper()
    if mrz_nationality:
        nat_match = mrz_nationality in viz_raw_text
        comparison['checks'].append({
            'name': 'Nationality Match (MRZ vs VIZ)',
            'passed': nat_match,
            'detail': f'MRZ: {mrz_nationality} | VIZ: {"Found in document" if nat_match else "Not found in document"}',
        })
        if not nat_match:
            # We don't fail the whole comparison for nationality as it's often represented differently (e.g., 'INDIAN' vs 'IND')
            comparison['checks'][-1]['warning'] = True
            comparison['checks'][-1]['passed'] = True

    return comparison
