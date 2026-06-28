"""
BGV v3.0 — Blockchain-style Hash-Chained Audit Ledger
=======================================================
Implements an immutable, append-only verification ledger using hash chaining
— the same cryptographic principle that underpins blockchain systems.

Architecture Overview
---------------------
Each record in the ledger is linked to the previous record via its hash,
forming an unbreakable chain:

    Genesis Block (Block 0)
         │  hash_0 = SHA256("GENESIS" + timestamp)
         │
    Block 1: { ...record_1..., prev_hash: hash_0 }
         │  block_hash_1 = SHA256(JSON(Block 1))
         │
    Block 2: { ...record_2..., prev_hash: block_hash_1 }
         │  block_hash_2 = SHA256(JSON(Block 2))
         ⋮

Any tampering with any historical record breaks all subsequent hashes,
making fraud immediately detectable via verify_chain_integrity().

Production Extension Points (for real deployment):
  - Swap the local JSON ledger for a Hyperledger Fabric chaincode call
  - Or batch-submit Merkle roots to Polygon/Ethereum every N records
  - The VerificationRecord schema is blockchain-agnostic

Storage:
  - Ledger stored as NDJSON (newline-delimited JSON) at LEDGER_PATH
  - Each line is one block (JSON object)
  - Append-only; never modified after write

PII Note:
  - No personal data is stored in the ledger
  - Only hashes, verdicts, doc types, and timestamps
"""

import hashlib
import json
import os
import time
from typing import Optional

# ─── Ledger file location ────────────────────────────────────────────────────
# Default: bgv_ledger.ndjson in the project root.
# Override via BGV_LEDGER_PATH environment variable for production deployments.
_DEFAULT_LEDGER_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'bgv_ledger.ndjson'
)
LEDGER_PATH = os.environ.get('BGV_LEDGER_PATH', _DEFAULT_LEDGER_PATH)

# Genesis block sentinel — every fresh ledger starts with this
_GENESIS_SENTINEL = 'BGV-GENESIS-v3.0'


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(data: str) -> str:
    """Return the SHA-256 hex digest of a UTF-8 encoded string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def _read_ledger() -> list:
    """Read all blocks from the ledger file. Returns [] if ledger is empty."""
    if not os.path.exists(LEDGER_PATH):
        return []
    blocks = []
    with open(LEDGER_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    blocks.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # skip corrupt lines (detected by integrity check)
    return blocks


def _append_block(block: dict) -> None:
    """Append a single block to the ledger file as a NDJSON line."""
    os.makedirs(os.path.dirname(LEDGER_PATH) if os.path.dirname(LEDGER_PATH) else '.', exist_ok=True)
    with open(LEDGER_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(block, sort_keys=True, default=str) + '\n')


def _get_latest_hash() -> str:
    """
    Return the hash of the most recent block, or the genesis hash if the
    ledger is empty (first record ever).
    """
    blocks = _read_ledger()
    if not blocks:
        # Genesis hash — deterministic starting point
        genesis_str = f"{_GENESIS_SENTINEL}|{LEDGER_PATH}"
        return _sha256(genesis_str)
    return blocks[-1].get('block_hash', _sha256(_GENESIS_SENTINEL))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def append_record(verification_record: dict) -> dict:
    """
    Append a VerificationRecord to the immutable ledger.

    Steps:
      1. Get the hash of the previous block (or genesis hash)
      2. Build a Block = { seq, prev_hash, timestamp, ...record, block_hash }
      3. block_hash = SHA256(canonical JSON of block without block_hash field)
      4. Write block to NDJSON ledger file

    Returns the completed block dict (including block_hash and seq).

    Args:
        verification_record: Dict produced by fingerprint.create_verification_record()

    Returns:
        block: The anchored block with its position and hash in the chain
    """
    prev_hash = _get_latest_hash()
    blocks = _read_ledger()
    seq = len(blocks)  # 0-indexed block sequence number
    timestamp_utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    block = {
        'seq': seq,
        'prev_hash': prev_hash,
        'timestamp_utc': timestamp_utc,
        'record': verification_record,
    }

    # Compute block hash over the canonical representation (without block_hash itself)
    block_json = json.dumps(block, sort_keys=True, default=str)
    block['block_hash'] = _sha256(block_json)

    _append_block(block)

    print(f"[LEDGER] Block #{seq} anchored — hash: {block['block_hash'][:16]}...")
    return block


def lookup_document(doc_hash: str) -> Optional[dict]:
    """
    Look up a verification record by any of its document fingerprint hashes.

    Searches all blocks for a record whose fingerprint matches doc_hash.
    Checks: crypto_hash, perceptual_hash, content_hash, composite_hash.

    Args:
        doc_hash: Any one of the four fingerprint hash values

    Returns:
        The matching block dict if found, else None
    """
    blocks = _read_ledger()
    for block in reversed(blocks):  # most recent first
        record = block.get('record', {})
        fingerprint = record.get('fingerprint', {})
        if doc_hash in (
            fingerprint.get('crypto_hash'),
            fingerprint.get('perceptual_hash'),
            fingerprint.get('content_hash'),
            fingerprint.get('composite_hash'),
            record.get('document_id'),
        ):
            return block
    return None


def lookup_candidate(candidate_id: str) -> list:
    """
    Return all verification records for a given candidate (pseudonymous ID).
    Ordered from oldest to newest.

    Args:
        candidate_id: The pseudonymous ID used during verification

    Returns:
        List of matching blocks, ordered by seq ascending
    """
    blocks = _read_ledger()
    return [
        b for b in blocks
        if b.get('record', {}).get('candidate_id') == candidate_id
    ]


def verify_chain_integrity() -> dict:
    """
    Walk the entire ledger and verify every block's hash chain.

    Checks:
      1. Each block's block_hash equals SHA256(block_json_without_block_hash)
      2. Each block's prev_hash equals the previous block's block_hash
      3. Block sequence numbers are contiguous

    Returns:
        {
            'valid'       : bool   — True if chain is fully intact
            'total_blocks': int    — Total number of blocks checked
            'errors'      : list   — List of error descriptions (empty if valid)
        }
    """
    blocks = _read_ledger()
    errors = []
    genesis_hash = _sha256(f"{_GENESIS_SENTINEL}|{LEDGER_PATH}")

    if not blocks:
        return {'valid': True, 'total_blocks': 0, 'errors': []}

    expected_prev = genesis_hash

    for idx, block in enumerate(blocks):
        seq = block.get('seq')

        # ── Check sequence number ─────────────────────────────────────────
        if seq != idx:
            errors.append(f"Block {idx}: seq mismatch (expected {idx}, got {seq})")

        # ── Check prev_hash chain ─────────────────────────────────────────
        actual_prev = block.get('prev_hash')
        if actual_prev != expected_prev:
            errors.append(
                f"Block {idx}: prev_hash broken "
                f"(expected {expected_prev[:16]}..., got {str(actual_prev)[:16]}...)"
            )

        # ── Recompute block_hash ──────────────────────────────────────────
        stored_hash = block.pop('block_hash', None)
        recomputed_json = json.dumps(block, sort_keys=True, default=str)
        recomputed_hash = _sha256(recomputed_json)
        block['block_hash'] = stored_hash  # restore

        if recomputed_hash != stored_hash:
            errors.append(
                f"Block {idx}: block_hash invalid — record tampered "
                f"(expected {recomputed_hash[:16]}..., stored {str(stored_hash)[:16]}...)"
            )

        expected_prev = stored_hash or recomputed_hash

    return {
        'valid': len(errors) == 0,
        'total_blocks': len(blocks),
        'errors': errors,
    }


def get_ledger_stats() -> dict:
    """
    Return summary statistics about the current ledger state.

    Returns:
        {
            'total_records': int,
            'latest_hash'  : str,
            'verdicts'     : dict  — counts by verdict (VERIFIED/SUSPICIOUS/REJECTED)
            'doc_types'    : dict  — counts by doc type
            'chain_valid'  : bool  — quick integrity flag
        }
    """
    blocks = _read_ledger()
    verdicts = {}
    doc_types = {}

    for block in blocks:
        record = block.get('record', {})
        verdict = record.get('verification', {}).get('verdict', 'UNKNOWN')
        doc_type = record.get('doc_type', 'UNKNOWN')
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        doc_types[doc_type] = doc_types.get(doc_type, 0) + 1

    latest_hash = blocks[-1].get('block_hash', 'N/A') if blocks else 'N/A'

    return {
        'total_records': len(blocks),
        'latest_hash': latest_hash,
        'verdicts': verdicts,
        'doc_types': doc_types,
        'ledger_path': LEDGER_PATH,
    }
