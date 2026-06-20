"""
BGV Pipeline 3: Tamper Detection Engine (Universal — High Precision)
=====================================================================
Applies to: Degree certificates, Payslips, Experience letters,
            Offer letters, Any uploaded document

Forensic Modules:
  A. Error Level Analysis (ELA) — Multi-quality JPEG compression variance
  B. Noise Inconsistency Analysis — Sensor noise pattern uniformity
  C. DCT Block Analysis — JPEG quantization block anomalies
  D. Copy-Move Detection — Self-copy/patch detection using block hashing
  E. Metadata Forensics — Creation tool, timestamps, raw byte signatures
"""

import os
import io
import re
import struct
import hashlib
import traceback
from datetime import datetime

from PIL import Image, ImageFilter, ImageChops
import numpy as np

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

import PyPDF2


def detect_tampering(filepath):
    """
    Main tamper detection pipeline.
    Runs all forensic modules and returns individual + aggregate scores.
    """
    result = {
        'pipeline': 'tamper',
        'checks': [],
        'flags': [],
        'module_scores': {},
        'tamper_score': 0.0,
    }

    # Load the document
    try:
        image, file_ext, raw_bytes, raw_text = load_document(filepath)
        result['raw_text'] = raw_text
        result['checks'].append({
            'name': 'Document Loading',
            'passed': True,
            'detail': f'Loaded as {file_ext.upper()} ({image.width}x{image.height})',
        })
    except Exception as e:
        result['checks'].append({
            'name': 'Document Loading',
            'passed': False,
            'detail': f'Failed: {str(e)}',
        })
        result['error'] = f'Cannot process document: {str(e)}'
        return result

    # Module A: Error Level Analysis (multi-quality, JPEG only)
    ela_result = run_ela(image, file_ext)
    result['module_scores']['ela'] = ela_result['score']
    result['checks'].append({
        'name': 'Error Level Analysis (ELA)',
        'passed': ela_result['score'] < 0.35,
        'warning': 0.2 <= ela_result['score'] < 0.35,
        'detail': f'Score: {ela_result["score"]:.2f} — {ela_result["detail"]}',
    })
    if ela_result['score'] >= 0.35:
        result['flags'].append({
            'module': 'ELA',
            'severity': 'HIGH' if ela_result['score'] >= 0.6 else 'MEDIUM',
            'description': ela_result['flag_desc'],
        })
    elif ela_result['score'] >= 0.2:
        result['flags'].append({
            'module': 'ELA',
            'severity': 'LOW',
            'description': ela_result['flag_desc'],
        })

    # Module B: Noise Inconsistency Analysis
    noise_result = run_noise_analysis(image)
    result['module_scores']['noise'] = noise_result['score']
    result['checks'].append({
        'name': 'Noise Inconsistency Analysis',
        'passed': noise_result['score'] < 0.35,
        'warning': 0.2 <= noise_result['score'] < 0.35,
        'detail': f'Score: {noise_result["score"]:.2f} — {noise_result["detail"]}',
    })
    if noise_result['score'] >= 0.35:
        result['flags'].append({
            'module': 'NOISE_ANALYSIS',
            'severity': 'HIGH' if noise_result['score'] >= 0.6 else 'MEDIUM',
            'description': noise_result['flag_desc'],
        })

    # Module C: DCT Block Coefficient Analysis
    dct_result = run_dct_block_analysis(image)
    result['module_scores']['dct'] = dct_result['score']
    result['checks'].append({
        'name': 'DCT Block Coefficient Analysis',
        'passed': dct_result['score'] < 0.35,
        'warning': 0.2 <= dct_result['score'] < 0.35,
        'detail': f'Score: {dct_result["score"]:.2f} — {dct_result["detail"]}',
    })
    if dct_result['score'] >= 0.35:
        result['flags'].append({
            'module': 'DCT_ANALYSIS',
            'severity': 'HIGH' if dct_result['score'] >= 0.6 else 'MEDIUM',
            'description': dct_result['flag_desc'],
        })

    # Module D: Copy-Move Patch Detection
    copy_result = run_copy_move_detection(image)
    result['module_scores']['copy_move'] = copy_result['score']
    result['checks'].append({
        'name': 'Copy-Move Patch Detection',
        'passed': copy_result['score'] < 0.35,
        'warning': 0.2 <= copy_result['score'] < 0.35,
        'detail': f'Score: {copy_result["score"]:.2f} — {copy_result["detail"]}',
    })
    if copy_result['score'] >= 0.35:
        result['flags'].append({
            'module': 'COPY_MOVE',
            'severity': 'HIGH',
            'description': copy_result['flag_desc'],
        })

    # Module E: Metadata Forensics
    meta_result = run_metadata_forensics(filepath, file_ext, raw_bytes)
    result['module_scores']['metadata'] = meta_result['score']
    result['checks'].append({
        'name': 'Metadata Forensics',
        'passed': meta_result['score'] < 0.4,
        'warning': 0.2 <= meta_result['score'] < 0.4,
        'detail': f'Score: {meta_result["score"]:.2f} — {meta_result["detail"]}',
    })
    if meta_result.get('flags'):
        for flag in meta_result['flags']:
            result['flags'].append(flag)

    # Aggregate tamper score (weighted — prioritize image forensics)
    weights = {
        'ela':       0.35,
        'noise':     0.30,
        'dct':       0.25,
        'copy_move': 0.05,
        'metadata':  0.05,
    }
    total_score = sum(
        result['module_scores'].get(m, 0) * w
        for m, w in weights.items()
    )
    result['tamper_score'] = round(total_score, 3)

    score_breakdown = ' + '.join(
        f'{m.upper()[:3]}: {result["module_scores"].get(m, 0):.2f}×{w:.2f}'
        for m, w in weights.items()
    )

    result['checks'].append({
        'name': 'Weighted Tamper Score',
        'passed': total_score < 0.25,
        'warning': 0.25 <= total_score < 0.50,
        'detail': f'Score: {total_score:.3f} ({score_breakdown})',
    })

    return result


# ============================================
# Document Loader
# ============================================

def load_document(filepath):
    """Load document as PIL Image, returning extension, raw bytes, and text (if PDF)."""
    ext = os.path.splitext(filepath)[1].lower()

    with open(filepath, 'rb') as f:
        raw_bytes = f.read()

    raw_text = ""
    if ext == '.pdf':
        try:
            import fitz
            doc = fitz.open(filepath)
            for page in doc:
                raw_text += page.get_text() + "\n"
            doc.close()
        except:
            pass

        image = pdf_to_image(filepath)
        return image, 'pdf', raw_bytes, raw_text
    else:
        image = Image.open(filepath)
        if image.mode == 'RGBA':
            image = image.convert('RGB')
        return image, ext.lstrip('.'), raw_bytes, ""


def pdf_to_image(filepath):
    """Render first page of PDF as a high-resolution RGB image using PyMuPDF."""
    try:
        import fitz
        doc = fitz.open(filepath)
        page = doc[0]
        mat = fitz.Matrix(2.0, 2.0)
        pix = page.get_pixmap(matrix=mat)
        image = Image.frombytes('RGB', [pix.width, pix.height], pix.samples)
        doc.close()
        return image
    except Exception as e:
        print(f"[WARN] fitz PDF to image conversion error: {e}")

    raise Exception("Cannot render PDF to image. Try uploading as JPG/PNG.")


# ============================================
# Module A: Error Level Analysis (Enhanced)
# ============================================

def run_ela(image, source_format='jpeg'):
    """
    Enhanced ELA — run at multiple JPEG quality levels and analyze
    per-block variance. Edited regions have inconsistent compression
    signatures across quality levels.
    
    NOTE: ELA only applies to JPEG images. PNG files are lossless and
    will always show a large ELA difference (false positive). This is
    skipped for lossless sources.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': 'ELA skipped (lossless source)'}

    # ELA only works on JPEG/lossy sources
    if source_format.lower() in ('png', 'pdf', 'bmp', 'tiff', 'tif', 'gif'):
        result['detail'] = f'Skipped — ELA requires a JPEG source (got {source_format.upper()})'
        result['flag_desc'] = 'ELA not applicable to lossless/rendered documents'
        return result

    try:
        if image.mode != 'RGB':
            image = image.convert('RGB')

        orig_array = np.array(image, dtype=np.float32)
        quality_scores = []

        # Test at 3 quality levels for more robust detection
        for quality in [75, 90, 95]:
            buf = io.BytesIO()
            image.save(buf, 'JPEG', quality=quality)
            buf.seek(0)
            resaved = np.array(Image.open(buf), dtype=np.float32)

            diff = np.abs(orig_array - resaved)
            quality_scores.append(diff)

        # Average difference map across all quality levels
        avg_diff = np.mean(quality_scores, axis=0)
        gray_diff = avg_diff.mean(axis=2)

        mean_d = np.mean(gray_diff)
        std_d  = np.std(gray_diff)

        # Coefficient of variation: high = inconsistent compression = edited
        cv = std_d / (mean_d + 1e-6)

        # Hotspot detection: pixels 2.5σ above mean are anomalous
        hotspot_threshold = mean_d + 2.5 * std_d
        hotspot_mask = gray_diff > hotspot_threshold
        hotspot_ratio = np.sum(hotspot_mask) / hotspot_mask.size

        # Cluster analysis — isolated hotspot clusters are suspicious
        if HAS_CV2:
            hm_uint8 = (hotspot_mask * 255).astype(np.uint8)
            n_labels, labels, stats, _ = cv2.connectedComponentsWithStats(hm_uint8)
            large_clusters = sum(1 for i in range(1, n_labels) if stats[i, cv2.CC_STAT_AREA] > 200)
        else:
            large_clusters = 0

        score = 0.0
        if cv > 2.0:     score += 0.35
        elif cv > 1.5:   score += 0.25
        elif cv > 1.0:   score += 0.15

        if hotspot_ratio > 0.08:   score += 0.35
        elif hotspot_ratio > 0.04: score += 0.20
        elif hotspot_ratio > 0.01: score += 0.10

        if large_clusters > 5:     score += 0.30
        elif large_clusters > 2:   score += 0.15

        result['score'] = min(round(score, 3), 1.0)
        result['detail'] = (
            f'CV={cv:.2f}, hotspots={hotspot_ratio:.2%}, '
            f'anomalous clusters={large_clusters}'
        )

        if score >= 0.5:
            result['flag_desc'] = (
                f'ELA — Strong compression inconsistencies detected '
                f'({large_clusters} isolated anomalous region(s)). '
                'Likely edited.'
            )
        elif score >= 0.2:
            result['flag_desc'] = 'ELA — Moderate compression variance. May warrant review.'
        else:
            result['flag_desc'] = 'ELA — Compression appears uniform.'

    except Exception as e:
        result['detail'] = f'ELA error: {str(e)}'
        result['flag_desc'] = 'ELA could not complete'
        traceback.print_exc()

    return result


# ============================================
# Module B: Noise Inconsistency Analysis
# ============================================

def run_noise_analysis(image):
    """
    Sensor noise analysis.
    
    Real documents (scanned or photographed) have consistent, spatially
    uniform sensor noise. Edited regions (pasted text, changed numbers)
    often come from a different image with a different noise signature.
    
    Method:
    - Divide image into NxN grid of blocks.
    - Estimate local noise variance for each block using a Laplacian filter.
    - Flag blocks whose noise variance deviates strongly from the global median.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': ''}

    try:
        if image.mode != 'RGB':
            gray = image.convert('L')
        else:
            gray = image.convert('L')

        gray_arr = np.array(gray, dtype=np.float64)
        h, w = gray_arr.shape

        block_size = max(32, min(h, w) // 16)
        noise_map = []

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = gray_arr[y:y+block_size, x:x+block_size]
                # Estimate noise as variance of high-frequency component
                # using a Laplacian kernel
                kernel = np.array([[0, -1, 0], [-1, 4, -1], [0, -1, 0]], dtype=np.float64)
                if HAS_CV2:
                    lap = cv2.filter2D(block, -1, kernel)
                else:
                    from scipy.ndimage import convolve
                    lap = convolve(block, kernel)
                noise_var = np.var(lap)
                noise_map.append(noise_var)

        if len(noise_map) < 4:
            result['detail'] = 'Document too small for noise analysis'
            result['score'] = 0.0
            return result

        noise_arr = np.array(noise_map)
        median_noise = np.median(noise_arr)
        mad = np.median(np.abs(noise_arr - median_noise))  # Median Absolute Deviation

        # Blocks with noise > 3.5 * MAD above/below median are anomalous
        threshold = 3.5 * (mad + 1e-6)
        anomalous_blocks = np.sum(np.abs(noise_arr - median_noise) > threshold)
        anomaly_ratio = anomalous_blocks / len(noise_arr)

        # Spread check: coefficient of variation of noise across blocks
        noise_cv = np.std(noise_arr) / (np.mean(noise_arr) + 1e-6)

        score = 0.0
        if anomaly_ratio > 0.20:   score += 0.40
        elif anomaly_ratio > 0.10: score += 0.25
        elif anomaly_ratio > 0.05: score += 0.10

        if noise_cv > 2.5:    score += 0.35
        elif noise_cv > 1.5:  score += 0.20
        elif noise_cv > 1.0:  score += 0.10

        result['score'] = min(round(score, 3), 1.0)
        result['detail'] = (
            f'{anomalous_blocks}/{len(noise_arr)} anomalous blocks '
            f'({anomaly_ratio:.1%}), noise CV={noise_cv:.2f}'
        )

        if score >= 0.5:
            result['flag_desc'] = (
                f'Noise — {anomalous_blocks} block(s) have significantly different '
                'noise signatures. This is a strong indicator of pasted content.'
            )
        elif score >= 0.2:
            result['flag_desc'] = 'Noise — Slight noise inconsistency. May warrant review.'
        else:
            result['flag_desc'] = 'Noise — Noise level appears spatially uniform.'

    except Exception as e:
        result['detail'] = f'Noise analysis error: {str(e)}'
        result['flag_desc'] = 'Noise analysis could not complete'

    return result


# ============================================
# Module C: DCT Block Coefficient Analysis
# ============================================

def run_dct_block_analysis(image):
    """
    DCT (Discrete Cosine Transform) Block Anomaly Detection.
    
    JPEG images are compressed in 8x8 pixel blocks. Each block's high-frequency
    DCT coefficients decay towards zero. When a region is edited and pasted
    from a different source, those 8x8 blocks will have different quantization
    tables and different coefficient distributions. This module tiles the
    image in 8x8 blocks and flags tiles whose AC energy is inconsistent
    with their neighbors.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': ''}

    try:
        if image.mode != 'L':
            gray = image.convert('L')
        else:
            gray = image

        gray_arr = np.array(gray, dtype=np.float64)
        h, w = gray_arr.shape

        # Only analyze if image is large enough
        if h < 64 or w < 64:
            result['detail'] = 'Image too small for DCT block analysis'
            return result

        BLOCK = 8
        energies = []

        for y in range(0, h - BLOCK, BLOCK):
            row_energies = []
            for x in range(0, w - BLOCK, BLOCK):
                block = gray_arr[y:y+BLOCK, x:x+BLOCK] - 128.0
                # Manual 2D DCT via numpy
                dct_block = _dct2d(block)
                # AC energy = total energy minus DC (top-left) term
                ac_energy = np.sum(dct_block ** 2) - dct_block[0, 0] ** 2
                row_energies.append(ac_energy)
            energies.append(row_energies)

        energy_arr = np.array(energies, dtype=np.float64)

        global_mean = np.mean(energy_arr)
        global_std  = np.std(energy_arr)

        # Blocks whose energy deviates by more than 3σ from the global are anomalous
        anomaly_mask = np.abs(energy_arr - global_mean) > 3.0 * global_std
        anomaly_ratio = np.sum(anomaly_mask) / anomaly_mask.size

        # Spatial clustering: check if anomalous blocks are clustered (paste region)
        # or random (normal noise)
        if HAS_CV2 and anomaly_ratio > 0.01:
            am_uint8 = (anomaly_mask * 255).astype(np.uint8)
            n_labels, _, stats, _ = cv2.connectedComponentsWithStats(am_uint8)
            # Large connected components = paste regions
            large_clusters = sum(1 for i in range(1, n_labels) if stats[i, cv2.CC_STAT_AREA] > 10)
        else:
            large_clusters = 0

        score = 0.0
        if anomaly_ratio > 0.15:   score += 0.40
        elif anomaly_ratio > 0.07: score += 0.25
        elif anomaly_ratio > 0.03: score += 0.10

        if large_clusters > 3:     score += 0.35
        elif large_clusters > 1:   score += 0.15

        result['score'] = min(round(score, 3), 1.0)
        result['detail'] = (
            f'{anomaly_ratio:.1%} anomalous DCT blocks, '
            f'{large_clusters} spatial cluster(s) detected'
        )

        if score >= 0.45:
            result['flag_desc'] = (
                f'DCT — {large_clusters} spatially-clustered DCT anomaly region(s) detected. '
                'This indicates content was spliced from a different image source.'
            )
        elif score >= 0.2:
            result['flag_desc'] = 'DCT — Moderate block coefficient anomalies detected.'
        else:
            result['flag_desc'] = 'DCT — Block coefficients appear consistent.'

    except Exception as e:
        result['detail'] = f'DCT error: {str(e)}'
        result['flag_desc'] = 'DCT analysis could not complete'

    return result


def _dct2d(block):
    """Compute 2D DCT using numpy separable 1D DCT."""
    n = block.shape[0]
    # Build DCT matrix
    idx = np.arange(n)
    k = idx.reshape(-1, 1)
    dct_mat = np.cos(np.pi * k * (2 * idx + 1) / (2 * n))
    dct_mat[0] *= 1 / np.sqrt(2)
    dct_mat *= np.sqrt(2 / n)
    return dct_mat @ block @ dct_mat.T


# ============================================
# Module D: Copy-Move Detection
# ============================================

def run_copy_move_detection(image):
    """
    Copy-Move / Patch Detection.
    
    Fraudsters often copy a clean area of a document and paste it
    over the area they want to hide. This creates two identical
    (or near-identical) blocks within the same image.
    
    Method: Divide image into overlapping blocks, compute perceptual
    hash (pHash) for each block, find blocks with near-identical hashes
    that are spatially distant. Uniform/blank blocks are filtered out
    to avoid background false-positives.
    """
    result = {'score': 0.0, 'detail': '', 'flag_desc': ''}

    try:
        if image.mode != 'L':
            gray = image.convert('L')
        else:
            gray = image

        img_arr = np.array(gray, dtype=np.uint8)
        h, w = img_arr.shape

        BLOCK = 32
        STEP  = 24  # Less overlap → fewer total blocks → faster, fewer false positives
        MIN_DIST = BLOCK * 4  # Must be at least 4 blocks away to count

        block_hashes = []  # (hash_int_64, cx, cy, std_dev)

        for y in range(0, h - BLOCK, STEP):
            for x in range(0, w - BLOCK, STEP):
                block = img_arr[y:y+BLOCK, x:x+BLOCK]
                std = np.std(block)
                # Skip very uniform blocks (blank spaces, white margins)
                if std < 8.0:
                    continue
                # Downsample to 8x8 for pHash
                small = np.array(
                    Image.fromarray(block).resize((8, 8), Image.LANCZOS),
                    dtype=np.float64
                )
                mean_val = np.mean(small)
                bits = (small > mean_val).flatten().astype(np.uint8)
                # Pack 64 bits to integer for fast comparison
                phash_int = int.from_bytes(np.packbits(bits).tobytes(), 'big')
                cx, cy = x + BLOCK // 2, y + BLOCK // 2
                block_hashes.append((phash_int, cx, cy))

        if len(block_hashes) < 10:
            result['detail'] = 'Insufficient content blocks for copy-move analysis'
            return result

        # Find near-duplicate blocks using Hamming distance ≤ 6 (allow minor compression noise)
        copy_pairs = 0
        for i in range(len(block_hashes)):
            for j in range(i + 1, len(block_hashes)):
                h1, x1, y1 = block_hashes[i]
                h2, x2, y2 = block_hashes[j]
                dist_px = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
                if dist_px < MIN_DIST:
                    continue
                # Hamming distance between the two pHashes
                xor = h1 ^ h2
                hamming = bin(xor).count('1')
                if hamming <= 3:  # Very strict — only pixel-perfect copies count
                    copy_pairs += 1

        score = 0.0
        if copy_pairs > 200:   score = 0.9
        elif copy_pairs > 80:  score = 0.7
        elif copy_pairs > 30:  score = 0.5
        elif copy_pairs > 10:  score = 0.3
        elif copy_pairs > 3:   score = 0.15

        result['score'] = round(score, 3)
        result['detail'] = f'{copy_pairs} near-duplicate content block pair(s) at distant positions'

        if score >= 0.5:
            result['flag_desc'] = (
                f'Copy-Move — {copy_pairs} duplicate content region(s) detected far apart. '
                'Strong indicator of cloned/pasted content.'
            )
        elif score >= 0.15:
            result['flag_desc'] = f'Copy-Move — {copy_pairs} potential clone region(s). Review recommended.'
        else:
            result['flag_desc'] = 'Copy-Move — No suspicious duplicate content regions detected.'

    except Exception as e:
        result['detail'] = f'Copy-move error: {str(e)}'
        result['flag_desc'] = 'Copy-move analysis could not complete'

    return result


# ============================================
# Module E: Metadata Forensics
# ============================================

def run_metadata_forensics(filepath, file_ext, raw_bytes):
    """
    Analyze document metadata for editing signatures.
    Checks creator tool, timestamps, and raw byte patterns.
    """
    result = {
        'score': 0.0,
        'detail': '',
        'flags': [],
        'metadata': {},
    }

    risk_signals = []

    try:
        if file_ext == 'pdf':
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
                meta = reader.metadata

                if meta:
                    result['metadata'] = {
                        'author':        str(meta.get('/Author', '')),
                        'creator':       str(meta.get('/Creator', '')),
                        'producer':      str(meta.get('/Producer', '')),
                        'creation_date': str(meta.get('/CreationDate', '')),
                        'mod_date':      str(meta.get('/ModDate', '')),
                        'title':         str(meta.get('/Title', '')),
                    }

                    creator  = str(meta.get('/Creator', '')).lower()
                    producer = str(meta.get('/Producer', '')).lower()

                    editing_tools = [
                        'photoshop', 'gimp', 'paint.net', 'pixlr',
                        'affinity', 'corel', 'inkscape', 'microsoft word',
                        'libre', 'openoffice'
                    ]
                    for tool in editing_tools:
                        if tool in creator or tool in producer:
                            risk_signals.append(('HIGH', f'Editing tool in metadata: {creator or producer}'))
                            break

                    online_editors = [
                        'canva', 'ilovepdf', 'smallpdf', 'sejda',
                        'pdf2go', 'pdfcandy', 'cleverpdf', 'hipdf',
                        'pdfescape', 'pdfbuddy', 'docfly'
                    ]
                    for editor in online_editors:
                        if editor in creator or editor in producer:
                            risk_signals.append(('HIGH', f'Online PDF editor: {creator or producer}'))
                            break

                    create_date = str(meta.get('/CreationDate', ''))
                    mod_date    = str(meta.get('/ModDate', ''))
                    if create_date and mod_date and create_date != mod_date:
                        risk_signals.append(('MEDIUM', f'ModDate != CreateDate (document was modified after creation)'))

                    num_pages = len(reader.pages)
                    result['metadata']['page_count'] = num_pages

            except Exception as e:
                result['detail'] = f'PDF metadata extraction partial: {str(e)}'

        else:
            try:
                img = Image.open(io.BytesIO(raw_bytes))
                exif = img.getexif()

                if exif:
                    software = exif.get(305, '')
                    if software:
                        result['metadata']['software'] = str(software)
                        sw_lower = str(software).lower()
                        editing_tools = ['photoshop', 'gimp', 'paint.net', 'pixlr', 'affinity']
                        for tool in editing_tools:
                            if tool in sw_lower:
                                risk_signals.append(('HIGH', f'EXIF software: {software}'))
                                break

                    datetime_original  = exif.get(36867, '')
                    datetime_digitized = exif.get(36868, '')
                    if datetime_original and datetime_digitized:
                        if str(datetime_original) != str(datetime_digitized):
                            risk_signals.append(('LOW', 'EXIF original and digitized timestamps differ'))
                else:
                    result['metadata']['exif'] = 'Stripped (no EXIF present)'

            except Exception:
                pass

        # Raw byte signature scan — catches tools that strip metadata but leave traces
        raw_str = raw_bytes[:20000].decode('latin-1', errors='ignore').lower()
        byte_signatures = {
            'adobe photoshop':      ('HIGH',   'Adobe Photoshop byte signature'),
            'gimp':                 ('HIGH',   'GIMP byte signature'),
            'paint.net':            ('HIGH',   'Paint.NET byte signature'),
            'inkscape':             ('MEDIUM', 'Inkscape byte signature'),
            'canva':                ('HIGH',   'Canva byte signature'),
            'ilovepdf':             ('HIGH',   'iLovePDF byte signature'),
            'smallpdf':             ('HIGH',   'SmallPDF byte signature'),
            'sejda':                ('MEDIUM', 'Sejda byte signature'),
        }
        for pattern, (sev, desc) in byte_signatures.items():
            if pattern in raw_str:
                if not any(pattern in s[1].lower() for s in risk_signals):
                    risk_signals.append((sev, desc + ' found in raw file bytes'))

        score = 0.0
        for severity, _ in risk_signals:
            if severity == 'HIGH':    score += 0.40
            elif severity == 'MEDIUM': score += 0.20
            elif severity == 'LOW':    score += 0.10

        result['score'] = min(score, 1.0)
        result['flags'] = [
            {'module': 'METADATA', 'severity': s, 'description': d}
            for s, d in risk_signals
        ]

        if risk_signals:
            result['detail'] = f'{len(risk_signals)} risk signal(s): {"; ".join(d for _, d in risk_signals[:2])}'
        else:
            result['detail'] = 'No suspicious metadata detected'

    except Exception as e:
        result['detail'] = f'Metadata error: {str(e)}'
        traceback.print_exc()

    return result
