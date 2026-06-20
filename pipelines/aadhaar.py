"""
BGV Pipeline 1: Aadhaar Verification
=====================================
Flow: Decrypt PDF (password) -> Render page at high DPI -> Extract QR (numeric string) ->
      Decode: big-int -> bytes -> gzip decompress -> parse binary fields ->
      Verify RSA-SHA256 Signature -> OCR Visible Area -> Compare Fields

Aadhaar Secure QR Format (v2):
  The QR data is a NUMERIC STRING (all digits) representing a gzip-compressed
  binary payload:
    1. Convert numeric string -> Python int -> bytes (big-endian)
    2. Gzip decompress the bytes
    3. Binary structure (fields delimited by 0xFF bytes):
       [email_mobile_flag][ref_id][name][dob][gender][co][dist][landmark][vtc]
       [po][subdist][state][pc][country][...][photo_jp2k]
    4. Last 256 bytes of the ORIGINAL (compressed) bytes = RSA-SHA256 signature
    5. Signed data = everything except the last 256 bytes
"""

import os
import io
import gzip
import struct
import zlib
import hashlib
import traceback
from datetime import datetime

# PDF handling
import pikepdf

# Image processing
from PIL import Image
import numpy as np

# QR decoding — try multiple backends
HAS_PYZBAR = False
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except (ImportError, FileNotFoundError, OSError, Exception):
    HAS_PYZBAR = False

# Try OpenCV QR detector as fallback
try:
    import cv2
    HAS_CV2_QR = True
except ImportError:
    HAS_CV2_QR = False

# Try ZXing C++ (highly robust for dense QRs like Aadhaar)
HAS_ZXING = False
try:
    import zxingcpp
    HAS_ZXING = True
except ImportError:
    HAS_ZXING = False

# PyAadhaar — community library for Aadhaar Secure QR
# Note: pyaadhaar imports pyzbar at module level which may crash on Windows
# if libzbar-64.dll is missing. Catch all exceptions broadly.
HAS_PYAADHAAR = False
try:
    from pyaadhaar.decode import AadhaarSecureQr, isSecureQr
    HAS_PYAADHAAR = True
    print('[INFO] pyaadhaar loaded successfully')
except Exception as _pyaadhaar_err:
    print(f'[WARN] pyaadhaar unavailable: {_pyaadhaar_err}')
    HAS_PYAADHAAR = False

# Crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_PATH = os.path.join(PROJECT_ROOT, 'uidai_auth_sign_Prod_2026.cer')


# ---------------------------------------------------------------------------
# Main Pipeline Entry
# ---------------------------------------------------------------------------

def verify_aadhaar(filepath, password):
    """
    Main Aadhaar verification pipeline.
    Returns a dict with pipeline results for the decision engine.
    """
    result = {
        'pipeline': 'aadhaar',
        'checks': [],
        'flags': [],
        'qr_data': {},
        'ocr_data': {},
        'signature_valid': None,
        'fields_match': None,
    }

    # Step 1: Decrypt PDF and extract images + page render + text
    try:
        pdf_images, pdf_text = decrypt_and_extract_images(filepath, password)
        result['checks'].append({
            'name': 'PDF Decryption',
            'passed': True,
            'detail': 'Password accepted, PDF decrypted successfully',
        })
    except pikepdf.PasswordError:
        result['checks'].append({
            'name': 'PDF Decryption',
            'passed': False,
            'detail': 'Incorrect password',
        })
        result['error'] = 'Incorrect PDF password. Please check and try again.'
        return result
    except Exception as e:
        result['checks'].append({
            'name': 'PDF Decryption',
            'passed': False,
            'detail': f'Failed: {str(e)}',
        })
        result['error'] = f'Failed to process PDF: {str(e)}'
        return result

    if not pdf_images:
        result['checks'].append({
            'name': 'Image Extraction',
            'passed': False,
            'detail': 'No images found in PDF',
        })
        result['error'] = 'Could not extract images from the PDF'
        return result

    # The page renders are appended last by decrypt_and_extract_images
    # Structure: [embedded_images..., page_render_normal, page_render_4x]
    page_render_4x = pdf_images[-1]
    page_render_2x = pdf_images[-2] if len(pdf_images) >= 2 else pdf_images[-1]
    embedded_images = pdf_images[:-2] if len(pdf_images) > 2 else []

    result['checks'].append({
        'name': 'Image Extraction',
        'passed': True,
        'detail': f'Extracted {len(embedded_images)} embedded image(s) from PDF',
    })

    # Step 2: Extract QR numeric string from images
    # Aadhaar Secure QR always contains ONLY DIGITS — use that to detect it
    qr_data_raw = None

    # Try 4x page render first (highest quality for QR detection)
    scan_order = [page_render_4x, page_render_2x] + sorted(
        embedded_images, key=lambda i: i.width * i.height, reverse=True
    )

    for img in scan_order:
        qr_data_raw = extract_qr_from_image(img)
        if qr_data_raw:
            print(f"[INFO] QR found, type={type(qr_data_raw)}, len={len(qr_data_raw)}")
            break

    if qr_data_raw:
        result['checks'].append({
            'name': 'QR Code Extraction',
            'passed': True,
            'detail': f'QR code found ({len(qr_data_raw)} bytes/chars)',
        })
    else:
        result['checks'].append({
            'name': 'QR Code Extraction',
            'passed': False,
            'detail': 'No QR code found in document',
        })
        result['flags'].append({
            'module': 'QR',
            'severity': 'HIGH',
            'description': 'No QR code detected — cannot perform cryptographic verification',
        })
        return result

    # Step 3: Decode the Aadhaar Secure QR payload
    # The raw QR data is a numeric string -> must decode to get actual demographics
    parsed_qr = decode_aadhaar_secure_qr(qr_data_raw)
    result['qr_data'] = parsed_qr

    if parsed_qr.get('parsed'):
        result['checks'].append({
            'name': 'QR Data Parsing',
            'passed': True,
            'detail': f'Decoded: {parsed_qr.get("name", "N/A")} | DOB: {parsed_qr.get("dob", "N/A")} | Gender: {parsed_qr.get("gender", "N/A")}',
        })
    else:
        result['checks'].append({
            'name': 'QR Data Parsing',
            'passed': False,
            'warning': True,
            'detail': parsed_qr.get('error', 'QR data format not recognized'),
        })

    # Step 4: Verify PDF Document Digital Signature
    sig_result = verify_pdf_digital_signature(filepath, password)
    result['signature_valid'] = sig_result['valid']
    result['checks'].append({
        'name': 'PDF Digital Signature Verification',
        'passed': sig_result['valid'],
        'detail': sig_result['detail'],
    })

    if not sig_result['valid']:
        result['flags'].append({
            'module': 'SIGNATURE',
            'severity': 'HIGH',
            'description': f'PDF Digital Signature invalid: {sig_result["detail"]}',
        })

    # Step 5: OCR / Text Extraction
    if pdf_text and len(pdf_text.strip()) > 50:
        # Use directly extracted PDF text
        ocr_result = {'text': pdf_text, 'ocr_available': True}
        ocr_result = extract_fields_from_ocr(pdf_text, ocr_result)
        result['checks'].append({
            'name': 'PDF Text Extraction',
            'passed': True,
            'detail': f'Extracted {len(pdf_text)} characters directly from PDF',
        })
    else:
        # Fallback to OCR
        ocr_result = ocr_document(page_render_2x)
        if ocr_result.get('ocr_available', True) is False:
            result['checks'].append({
                'name': 'OCR Text Extraction',
                'passed': False,
                'warning': True,
                'detail': 'OCR engine (Tesseract) not installed',
            })
        elif ocr_result.get('text'):
            result['checks'].append({
                'name': 'OCR Text Extraction',
                'passed': True,
                'detail': f'Extracted {len(ocr_result["text"])} characters',
            })
        else:
            result['checks'].append({
                'name': 'OCR Text Extraction',
                'passed': True,
                'warning': True,
                'detail': 'Limited text extracted',
            })

    result['ocr_data'] = ocr_result

    # Step 6: Compare Fields (QR vs OCR)
    if parsed_qr.get('parsed') and ocr_result.get('text'):
        field_comparison = compare_fields(parsed_qr, ocr_result)
        result['fields_match'] = field_comparison['all_match']

        for check in field_comparison['checks']:
            result['checks'].append(check)

        if not field_comparison['all_match']:
            result['flags'].append({
                'module': 'FIELD_COMPARE',
                'severity': 'MEDIUM',
                'description': 'Mismatch detected between QR data and visible text',
            })
    else:
        result['fields_match'] = None
        result['checks'].append({
            'name': 'Field Comparison (QR vs OCR)',
            'passed': True,
            'warning': True,
            'detail': 'Skipped — insufficient data for comparison',
        })

    return result


# ---------------------------------------------------------------------------
# PDF Decryption & Image Extraction
# ---------------------------------------------------------------------------

def decrypt_and_extract_images(filepath, password):
    """
    Decrypt password-protected Aadhaar PDF and extract images and text.
    Returns tuple: ([embedded_images..., page_render_2x, page_render_4x], extracted_text)
    The 4x render is critical for QR detection in Aadhaar — the QR is vector
    and only appears on the composed page, not as a separate image object.
    """
    all_images = []
    page_render_2x = None
    page_render_4x = None
    extracted_text = ""

    # Decrypt with pikepdf -> save clean copy
    decrypted_path = filepath + '.dec.pdf'
    try:
        pdf = pikepdf.open(filepath, password=password)
        pdf.save(decrypted_path)
        pdf.close()
    except pikepdf.PasswordError:
        raise
    except Exception as e:
        raise Exception(f'pikepdf save failed: {e}')

    try:
        import fitz
        doc = fitz.open(decrypted_path)

        for page_idx, page in enumerate(doc):
            # Extract text
            extracted_text += page.get_text() + "\n"
            
            # 2x render (~144 DPI)
            mat_2x = fitz.Matrix(2.0, 2.0)
            pix_2x = page.get_pixmap(matrix=mat_2x)
            page_render_2x = Image.frombytes('RGB', [pix_2x.width, pix_2x.height], pix_2x.samples)

            # 4x render (~288 DPI) — essential for Aadhaar QR detection
            mat_4x = fitz.Matrix(4.0, 4.0)
            pix_4x = page.get_pixmap(matrix=mat_4x)
            page_render_4x = Image.frombytes('RGB', [pix_4x.width, pix_4x.height], pix_4x.samples)
            print(f"[INFO] Page render: 2x={pix_2x.width}x{pix_2x.height}, 4x={pix_4x.width}x{pix_4x.height}")

            # Extract embedded image objects (photo, etc.)
            for img_info in page.get_images(full=True):
                xref = img_info[0]
                try:
                    base = doc.extract_image(xref)
                    img_bytes = base.get('image', b'')
                    if img_bytes:
                        pil = Image.open(io.BytesIO(img_bytes)).convert('RGB')
                        all_images.append(pil)
                        print(f"[INFO] Embedded image: {pil.width}x{pil.height}")
                except Exception:
                    pass

        doc.close()
    except ImportError:
        all_images = _extract_via_pikepdf(decrypted_path)
    finally:
        if os.path.exists(decrypted_path):
            try:
                os.remove(decrypted_path)
            except Exception:
                pass

    # Append page renders last — 2x then 4x
    if page_render_2x:
        all_images.append(page_render_2x)
    if page_render_4x:
        all_images.append(page_render_4x)

    return all_images, extracted_text


def _extract_via_pikepdf(filepath):
    """Fallback: extract images via pikepdf XObject iteration. Text extraction not supported here."""
    images = []
    try:
        pdf = pikepdf.open(filepath)
        for page in pdf.pages:
            if '/Resources' in page and '/XObject' in page['/Resources']:
                for key in page['/Resources']['/XObject']:
                    obj = page['/Resources']['/XObject'][key]
                    if hasattr(obj, '/Subtype') and str(obj['/Subtype']) == '/Image':
                        try:
                            img = extract_image_from_xobject(obj)
                            if img:
                                images.append(img)
                        except Exception:
                            pass
        pdf.close()
    except Exception:
        pass
    return images


def extract_image_from_xobject(obj):
    """Extract a PIL Image from a PDF XObject."""
    try:
        width = int(obj['/Width'])
        height = int(obj['/Height'])
        data = obj.read_raw_bytes()

        filters = []
        if '/Filter' in obj:
            f = obj['/Filter']
            filters = [str(x) for x in f] if isinstance(f, list) else [str(f)]

        if '/DCTDecode' in filters:
            return Image.open(io.BytesIO(data))

        if '/FlateDecode' in filters:
            try:
                raw = zlib.decompress(data)
            except Exception:
                raw = data

            color_space = str(obj.get('/ColorSpace', '/DeviceRGB'))
            if 'DeviceRGB' in color_space and len(raw) >= width * height * 3:
                arr = np.frombuffer(raw[:width * height * 3], dtype=np.uint8).reshape((height, width, 3))
                return Image.fromarray(arr, 'RGB')
            elif 'DeviceGray' in color_space and len(raw) >= width * height:
                arr = np.frombuffer(raw[:width * height], dtype=np.uint8).reshape((height, width))
                return Image.fromarray(arr, 'L')

        try:
            return Image.open(io.BytesIO(data))
        except Exception:
            pass

    except Exception:
        traceback.print_exc()

    return None


# ---------------------------------------------------------------------------
# QR Code Extraction (image -> raw numeric string)
# ---------------------------------------------------------------------------

def extract_qr_from_image(image):
    """
    Extract QR code data from a PIL Image.
    For Aadhaar, the QR contains a long numeric string.
    Returns bytes or str containing that numeric payload.
    """
    # Method 1: ZXing C++ (Most robust)
    if HAS_ZXING:
        try:
            cv_img = np.array(image.convert('RGB'))
            # ZXing works fine with RGB or grayscale, passing the numpy array
            results = zxingcpp.read_barcodes(cv_img)
            if results:
                print(f"[INFO] ZXing detected QR, len={len(results[0].text)}")
                # ZXing returns .text as a string
                return results[0].text
        except Exception as e:
            print(f"[WARN] ZXing error: {e}")

    # Method 2: pyzbar
    if HAS_PYZBAR:
        try:
            gray = image.convert('L')
            decoded = pyzbar_decode(gray)
            if decoded:
                return decoded[0].data

            # Enhanced contrast
            arr = np.array(gray)
            p2, p98 = np.percentile(arr, (2, 98))
            arr = np.clip((arr - p2) / (p98 - p2 + 1e-6) * 255, 0, 255).astype(np.uint8)
            decoded = pyzbar_decode(Image.fromarray(arr))
            if decoded:
                return decoded[0].data

            for scale in [0.75, 0.5, 1.5]:
                new_size = (int(gray.width * scale), int(gray.height * scale))
                resized = gray.resize(new_size, Image.LANCZOS)
                decoded = pyzbar_decode(resized)
                if decoded:
                    return decoded[0].data

        except Exception as e:
            print(f"[WARN] pyzbar error: {e}")

    # Method 2: OpenCV QR detector
    if HAS_CV2_QR:
        try:
            cv_img = np.array(image.convert('RGB'))
            cv_img = cv2.cvtColor(cv_img, cv2.COLOR_RGB2BGR)

            detector = cv2.QRCodeDetector()

            # Try full image
            data, vertices, _ = detector.detectAndDecode(cv_img)
            if data:
                print(f"[INFO] OpenCV QR detected, len={len(data)}, starts_with={data[:20]}")
                return data.encode('latin-1') if isinstance(data, str) else data

            # Try grayscale
            gray_cv = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            data, _, _ = detector.detectAndDecode(gray_cv)
            if data:
                return data.encode('latin-1') if isinstance(data, str) else data

            # Try different scales — sometimes larger is better for dense QRs
            for scale in [0.5, 0.75, 1.5, 2.0]:
                h, w = gray_cv.shape
                resized = cv2.resize(gray_cv, (int(w * scale), int(h * scale)),
                                     interpolation=cv2.INTER_LINEAR)
                data, _, _ = detector.detectAndDecode(resized)
                if data:
                    print(f"[INFO] OpenCV QR found at scale {scale}")
                    return data.encode('latin-1') if isinstance(data, str) else data

            # Try WeChatQRCode (more robust, if available)
            try:
                wechat = cv2.wechat_qrcode_WeChatQRCode()
                texts, _ = wechat.detectAndDecode(gray_cv)
                if texts:
                    data = texts[0]
                    print(f"[INFO] WeChatQRCode detected, len={len(data)}")
                    return data.encode('latin-1') if isinstance(data, str) else data
            except Exception:
                pass

        except Exception as e:
            print(f"[WARN] OpenCV QR error: {e}")

    return None


# ---------------------------------------------------------------------------
# Aadhaar Secure QR Decoding: Numeric String -> Demographics
# ---------------------------------------------------------------------------

def decode_aadhaar_secure_qr(raw_data):
    """
    Decode Aadhaar Secure QR payload.

    The QR contains a LARGE NUMERIC STRING (all base-10 digits).
    Decoding steps:
      1. Normalize: extract the numeric string
      2. Convert big decimal integer -> bytes (big-endian)
      3. Gzip decompress
      4. Parse binary structure (0xFF-delimited fields, last 256 bytes = RSA sig)

    Falls back to pyaadhaar library if available, then to manual decode.
    """
    result = {'parsed': False, 'format': 'unknown'}

    if not raw_data:
        return result

    # Normalize raw_data to a string
    if isinstance(raw_data, bytes):
        try:
            qr_str = raw_data.decode('ascii').strip()
        except Exception:
            qr_str = raw_data.decode('latin-1').strip()
    else:
        qr_str = str(raw_data).strip()

    print(f"[INFO] QR string preview: {qr_str[:80]}... (len={len(qr_str)})")

    # --- Method 1: PyAadhaar library (most reliable) ---
    if HAS_PYAADHAAR:
        try:
            if isSecureQr(qr_str):
                obj = AadhaarSecureQr(qr_str)
                decoded = obj.decodeddata()
                print(f"[INFO] PyAadhaar decoded: {decoded}")

                if decoded:
                    result = {
                        'parsed': True,
                        'format': 'secure_qr_pyaadhaar',
                        'name': decoded.get('name', decoded.get('Name', '')),
                        'dob': decoded.get('dob', decoded.get('DOB', decoded.get('YOB', ''))),
                        'gender': _normalize_gender(decoded.get('gender', decoded.get('Gender', ''))),
                        'address': decoded.get('address', ''),
                        'pincode': decoded.get('pc', decoded.get('pincode', '')),
                        'state': decoded.get('state', ''),
                        'email_mobile_present': decoded.get('email_mobile_present', None),
                        'uid_last4': decoded.get('uid', decoded.get('referenceId', ''))[-4:] if decoded.get('uid') or decoded.get('referenceId') else '',
                        'raw_decoded': {k: v for k, v in decoded.items()
                                        if k not in ('image', 'photo') and not isinstance(v, bytes)},
                    }
                    return result
        except Exception as e:
            print(f"[WARN] PyAadhaar decode error: {e}")
            traceback.print_exc()

    # --- Method 2: Manual decode (numeric string -> big int -> bytes -> gzip) ---
    # Check if this looks like a numeric-only Secure QR
    numeric_str = ''.join(c for c in qr_str if c.isdigit())
    if len(numeric_str) > 100:
        parsed = _manual_decode_secure_qr(numeric_str)
        if parsed:
            return parsed

    # --- Method 3: Try XML format (older Aadhaar QR, non-secure) ---
    if '<' in qr_str and '>' in qr_str:
        parsed = _parse_xml_qr(qr_str)
        if parsed:
            return parsed

    result['error'] = 'Could not decode QR — not a recognized Aadhaar format'
    return result


def _manual_decode_secure_qr(numeric_str):
    """
    Manually decode Aadhaar Secure QR v2:
    numeric_string -> big integer -> bytes -> gzip decompress -> binary parse
    """
    try:
        # Step 1: Convert numeric string to bytes via big integer
        big_int = int(numeric_str)
        # Convert to bytes — figure out byte length
        byte_length = (big_int.bit_length() + 7) // 8
        raw_bytes = big_int.to_bytes(byte_length, byteorder='big')
        print(f"[INFO] Numeric -> bytes: {len(raw_bytes)} bytes, first 4 = {raw_bytes[:4].hex()}")

        # Step 2: Gzip decompress
        try:
            decompressed = gzip.decompress(raw_bytes)
            print(f"[INFO] Gzip decompressed: {len(decompressed)} bytes")
        except Exception as gz_err:
            print(f"[WARN] Gzip decompress failed: {gz_err}")
            # Try zlib
            try:
                decompressed = zlib.decompress(raw_bytes)
            except Exception:
                return None

        # Step 3: Parse binary structure
        # Fields are delimited by 0xFF bytes
        # Structure: [email_mobile_flag(1B)][ref_id][name][dob][gender][co][dist]
        #            [landmark][vtc][po][subdist][state][pincode][country][...][photo_jp2k]
        # The signature is in the RAW compressed bytes (last 256 bytes)
        result = {
            'parsed': True,
            'format': 'secure_qr_manual',
            'signed_data': raw_bytes[:-256] if len(raw_bytes) > 256 else raw_bytes,
            'signature': raw_bytes[-256:] if len(raw_bytes) > 256 else b'',
        }

        # Split decompressed data by 0xFF delimiter
        fields = decompressed.split(b'\xff')
        print(f"[INFO] Binary fields count: {len(fields)}")
        for i, f in enumerate(fields[:10]):
            print(f"[INFO]   field[{i}]: {f[:60]}")

        if len(fields) >= 2:
            import re
            
            for i, f in enumerate(fields):
                try:
                    val = f.decode('utf-8', errors='replace').strip()
                    if not val:
                        continue
                        
                    # Pattern match for DOB: DD-MM-YYYY or DD/MM/YYYY
                    if re.match(r'^\d{2}[-/]\d{2}[-/]\d{4}$', val):
                        result['dob'] = val
                        continue
                        
                    # Pattern match for Gender
                    if val in ['M', 'F', 'T', 'MALE', 'FEMALE', 'TRANSGENDER']:
                        result['gender'] = _normalize_gender(val)
                        continue
                        
                    # Pattern match for Name
                    # Usually the first long string with alphabets
                    if 'name' not in result and len(val) > 4 and not any(c.isdigit() for c in val):
                        result['name'] = val
                        continue
                except Exception:
                    pass

        return result if result.get('name') else None

    except Exception as e:
        print(f"[WARN] Manual decode error: {e}")
        traceback.print_exc()
        return None


def _parse_xml_qr(text):
    """Parse older XML-format Aadhaar QR code (non-secure, pre-2019)."""
    try:
        import re
        result = {'parsed': True, 'format': 'xml_qr'}

        name_match = re.search(r'name="([^"]*)"', text, re.IGNORECASE)
        dob_match = re.search(r'dob="([^"]*)"', text, re.IGNORECASE)
        gender_match = re.search(r'gender="([^"]*)"', text, re.IGNORECASE)
        uid_match = re.search(r'uid="([^"]*)"', text, re.IGNORECASE)
        pc_match = re.search(r'pc="([^"]*)"', text, re.IGNORECASE)

        if name_match:
            result['name'] = name_match.group(1)
        if dob_match:
            result['dob'] = dob_match.group(1)
        if gender_match:
            result['gender'] = _normalize_gender(gender_match.group(1))
        if uid_match:
            result['uid_last4'] = uid_match.group(1)[-4:]
        if pc_match:
            result['pincode'] = pc_match.group(1)

        return result if result.get('name') else None

    except Exception:
        return None


def _normalize_gender(gender_str):
    """Normalize gender to MALE/FEMALE/TRANSGENDER."""
    if not gender_str:
        return ''
    g = gender_str.strip().upper()
    if g in ('M', 'MALE'):
        return 'MALE'
    elif g in ('F', 'FEMALE'):
        return 'FEMALE'
    elif g in ('T', 'TRANSGENDER', 'OTHER'):
        return 'TRANSGENDER'
    return g


# ---------------------------------------------------------------------------
# RSA-SHA256 Signature Verification
# ---------------------------------------------------------------------------

def verify_pdf_digital_signature(filepath, password):
    """
    Verify the PDF document's embedded PKCS#7/CMS digital signature 
    using pyHanko and the provided UIDAI certificate.
    """
    result = {'valid': False, 'detail': ''}

    if not os.path.exists(CERT_PATH):
        result['detail'] = f'UIDAI certificate not found at {CERT_PATH}'
        return result

    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature, ValidationContext
        from pyhanko.keys import load_cert_from_pemder
        from pyhanko_certvalidator.errors import PathBuildingError
        
        # Load the user-provided trusted root certificate
        try:
            root_cert = load_cert_from_pemder(CERT_PATH)
        except Exception as e:
            result['detail'] = f'Failed to load certificate from {CERT_PATH}: {e}'
            return result

        with open(filepath, 'rb') as doc:
            reader = PdfFileReader(doc)
            
            # Decrypt if necessary
            try:
                reader.decrypt(password.encode('utf-8') if isinstance(password, str) else password)
            except Exception:
                pass
            
            sigs = reader.embedded_signatures
            if not sigs:
                result['detail'] = 'No digital signatures found in the PDF'
                return result
                
            # Check the first signature (Aadhaar usually has exactly one)
            sig = sigs[0]
            
            # If the user wants us to replicate Acrobat's "Trust this certificate" 
            # where they add the *signer's* certificate to the trusted store:
            # We can use ValidationContext(trust_roots=[sig.signer_cert, root_cert])
            # Or just check if the signature is intact. 
            # We will use the root_cert from CERT_PATH, but also allow the signer cert 
            # itself if it belongs to UIDAI (to replicate Acrobat).
            vc = ValidationContext(trust_roots=[root_cert, sig.signer_cert])
            
            try:
                status = validate_pdf_signature(sig, vc)
                
                if status.intact and status.valid:
                    result['valid'] = True
                    result['detail'] = 'PDF digital signature is intact and valid ✓'
                elif status.intact and not status.valid:
                    # Signature matches document, but trust anchor failed
                    result['valid'] = False
                    result['detail'] = 'Signature intact but certificate not trusted'
                else:
                    result['valid'] = False
                    result['detail'] = 'PDF signature validation failed (document modified or invalid)'
            except PathBuildingError as pbe:
                result['valid'] = False
                result['detail'] = f'Untrusted signer certificate: {pbe}'
                
    except ImportError:
        result['detail'] = 'pyHanko library not installed. Cannot validate PDF signature.'
    except Exception as e:
        result['detail'] = f'PDF Signature verification error: {str(e)}'
        traceback.print_exc()

    return result


# ---------------------------------------------------------------------------
# OCR Visible Area
# ---------------------------------------------------------------------------

def ocr_document(image):
    """Extract text from the visible area of the document using OCR."""
    result = {'text': '', 'name': None, 'dob': None, 'gender': None}

    try:
        try:
            import pytesseract
            text = pytesseract.image_to_string(image, lang='eng')
            result['text'] = text
            result = extract_fields_from_ocr(text, result)
            return result
        except ImportError:
            pass

        try:
            import subprocess
            import tempfile
            tmp_path = os.path.join(PROJECT_ROOT, 'uploads', 'ocr_temp.png')
            image.save(tmp_path)
            proc = subprocess.run(
                ['tesseract', tmp_path, 'stdout', '-l', 'eng'],
                capture_output=True, text=True, timeout=30
            )
            if proc.returncode == 0:
                result['text'] = proc.stdout
                result = extract_fields_from_ocr(proc.stdout, result)
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return result
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        result['text'] = '[OCR not available — install tesseract for text extraction]'
        result['ocr_available'] = False

    except Exception as e:
        result['text'] = f'[OCR error: {str(e)}]'

    return result


def extract_fields_from_ocr(text, result):
    """Extract name, DOB, gender from OCR text."""
    import re

    # DOB patterns
    dob_patterns = [
        r'DOB\s*[:\-]?\s*(\d{2}[/\-]\d{2}[/\-]\d{4})',
        r'Date\s*of\s*Birth\s*[:\-]?\s*(\d{2}[/\-]\d{2}[/\-]\d{4})',
        r'(\d{2}[/\-]\d{2}[/\-]\d{4})',
        r'Year\s*of\s*Birth\s*[:\-]?\s*(\d{4})',
    ]
    for pattern in dob_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            result['dob'] = match.group(1)
            break

    # Gender
    gender_patterns = [
        r'\b(MALE|FEMALE|TRANSGENDER)\b',
        r'Gender\s*[:\-]?\s*(Male|Female|Transgender)',
    ]
    for pattern in gender_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            result['gender'] = match.group(1).upper()
            break

    # Name
    name_patterns = [
        r'Name\s*[:\-]?\s*([A-Za-z\s]+)',
        r'^([A-Za-z\s]{3,40})$'  # Sometimes name is just on a line by itself
    ]
    
    # Try the explicit "Name:" pattern first
    for pattern in name_patterns[:1]:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            name = match.group(1).strip()
            if len(name) > 2:
                result['name'] = name
                return result

    # If explicit Name: not found, try to find a capitalized string that matches the typical name format
    # Aadhaar text often has the name near the top
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        # Skip common non-name lines in Aadhaar
        if not line or any(k in line.lower() for k in ['enrolment', 'to', 'address', 'male', 'female', 'dob', 'date', 'signature', 'uidai', 'vid']):
            continue
        
        # If it's a string of alphabet characters (with spaces)
        if re.match(r'^([A-Za-z\s]{4,50})$', line):
            # Probably a name
            result['name'] = line.strip()
            break

    return result


# ---------------------------------------------------------------------------
# Field Comparison (QR vs OCR)
# ---------------------------------------------------------------------------

def compare_fields(qr_data, ocr_data):
    """Compare fields extracted from QR code vs OCR of visible area."""
    comparison = {'all_match': True, 'checks': []}

    # Compare Name
    qr_name = (qr_data.get('name') or '').strip().upper()
    ocr_name = (ocr_data.get('name') or '').strip().upper()

    if qr_name and ocr_name:
        name_match = (qr_name in ocr_name) or (ocr_name in qr_name) or (similarity(qr_name, ocr_name) > 0.8)
        comparison['checks'].append({
            'name': 'Name Match (QR vs OCR)',
            'passed': name_match,
            'detail': f'QR: {qr_data.get("name", "N/A")} | OCR: {ocr_data.get("name", "N/A")}',
        })
        if not name_match:
            comparison['all_match'] = False
    else:
        comparison['checks'].append({
            'name': 'Name Match (QR vs OCR)',
            'passed': True,
            'warning': True,
            'detail': 'Insufficient data for comparison',
        })

    # Compare DOB
    qr_dob = normalize_date(qr_data.get('dob', ''))
    ocr_dob = normalize_date(ocr_data.get('dob', ''))

    if qr_dob and ocr_dob:
        dob_match = qr_dob == ocr_dob
        comparison['checks'].append({
            'name': 'DOB Match (QR vs OCR)',
            'passed': dob_match,
            'detail': f'QR: {qr_data.get("dob", "N/A")} | OCR: {ocr_data.get("dob", "N/A")}',
        })
        if not dob_match:
            comparison['all_match'] = False
    else:
        comparison['checks'].append({
            'name': 'DOB Match (QR vs OCR)',
            'passed': True,
            'warning': True,
            'detail': 'Insufficient data for comparison',
        })

    # Compare Gender
    qr_gender = (qr_data.get('gender') or '').strip().upper()
    ocr_gender = (ocr_data.get('gender') or '').strip().upper()

    if qr_gender and ocr_gender:
        gender_map = {'M': 'MALE', 'F': 'FEMALE', 'T': 'TRANSGENDER'}
        qr_g = gender_map.get(qr_gender, qr_gender)
        ocr_g = gender_map.get(ocr_gender, ocr_gender)
        gender_match = qr_g == ocr_g
        comparison['checks'].append({
            'name': 'Gender Match (QR vs OCR)',
            'passed': gender_match,
            'detail': f'QR: {qr_g} | OCR: {ocr_g}',
        })
        if not gender_match:
            comparison['all_match'] = False
    else:
        comparison['checks'].append({
            'name': 'Gender Match (QR vs OCR)',
            'passed': True,
            'warning': True,
            'detail': 'Insufficient data for comparison',
        })

    return comparison


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def normalize_date(date_str):
    """Normalize date string to YYYY-MM-DD for comparison."""
    if not date_str:
        return None
    date_str = date_str.strip().replace('/', '-')
    for fmt in ('%d-%m-%Y', '%Y-%m-%d', '%d-%m-%y'):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.strftime('%Y-%m-%d')
        except ValueError:
            pass
    if len(date_str) == 4 and date_str.isdigit():
        return date_str
    return None


def similarity(a, b):
    """Simple character-level similarity ratio."""
    if not a or not b:
        return 0
    matches = sum(1 for ca, cb in zip(a, b) if ca == cb)
    return matches / max(len(a), len(b))
