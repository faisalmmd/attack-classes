"""
WebAssembly Security Scanner
Tests: cryptominer detection via binary signatures and export/section name analysis
"""

import re
import struct
from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    test_name: str
    severity: str
    file_path: str
    line_number: int  # 0 for binary files
    line_content: str
    description: str


class WASMScanner:
    """Runs WASM security tests on .wasm binary files."""

    EXTENSIONS = {".wasm"}

    # WASM magic number: \0asm
    WASM_MAGIC = b'\x00asm'

    # Known cryptominer WASM file hashes (SHA256)
    # Add known hashes from your threat intel feeds
    KNOWN_MINER_HASHES = {
        # Placeholder — populate with real hashes from:
        # https://github.com/nicehash/miner-plugins
        # MineSweeper, MinerRay publications
    }

    # Strings found in known mining WASM modules
    MINER_SIGNATURES_BYTES = [
        b'cryptonight',
        b'CryptoNight',
        b'cn_slow_hash',
        b'cn_fast_hash',
        b'scratchpad',
        b'stratum',
        b'mining',
        b'hashrate',
        b'nonce',
        b'keccak',
        b'blake256',
        b'groestl',
        b'jh_hash',
        b'skein',
        b'randomx',
        b'RandomX',
        b'argon2',
        b'Argon2',
        b'equihash',
        b'ethash',
        b'scrypt',
        b'monero',
        b'coinhive',
        b'CoinHive',
        b'cryptoloot',
        b'CryptoLoot',
        b'xmrig',
        b'xmr-stak',
    ]

    # Mining-related export/function names
    MINER_EXPORT_NAMES = [
        'hash', 'mine', 'miner', 'start_mining', 'stop_mining',
        'get_hashrate', 'set_throttle', 'cn_hash', 'cryptonight',
        'scrypt_hash', 'randomx_hash', 'argon2_hash',
        'scratchpad_init', 'slow_hash', 'fast_hash',
        'work', 'nonce', 'submit', 'job',
    ]

    def scan(self, file_path: str) -> List[Finding]:
        """Run all WASM tests on one file."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return []

        findings = []

        # Validate WASM magic
        if not data[:4] == self.WASM_MAGIC:
            return findings

        # Get version


        findings.extend(self._test_cryptominer_signatures(file_path, data))
        findings.extend(self._test_cryptominer_exports(file_path, data))
        findings.extend(self._test_file_hash(file_path, data))
        findings.extend(self._test_suspicious_size(file_path, data))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 19a: Cryptominer Binary Signatures
    # ------------------------------------------------------------------ #
    def _test_cryptominer_signatures(self, fp: str, data: bytes) -> List[Finding]:
        """
        Scan WASM binary for byte sequences associated with known
        cryptocurrency mining algorithms and libraries.
        """
        findings = []
        found_sigs = []

        for sig in self.MINER_SIGNATURES_BYTES:
            # Case-insensitive byte search
            idx = data.lower().find(sig.lower())
            if idx != -1:
                # Get context around the match
                context_start = max(0, idx - 20)
                context_end = min(len(data), idx + len(sig) + 20)
                context = data[context_start:context_end]
                # Make printable
                context_str = ''.join(
                    chr(b) if 32 <= b < 127 else '.' for b in context
                )
                found_sigs.append(sig.decode('utf-8', errors='replace'))
                findings.append(Finding(
                    "wasm_cryptominer", "HIGH", fp, 0,
                    f"...{context_str}...",
                    f"Mining signature found: '{sig.decode('utf-8', errors='replace')}' "
                    f"at byte offset {idx}"
                ))

        # If multiple mining signatures, escalate to CRITICAL
        if len(found_sigs) >= 3:
            findings.append(Finding(
                "wasm_cryptominer", "CRITICAL", fp, 0,
                ", ".join(found_sigs[:10]),
                f"Found {len(found_sigs)} distinct mining signatures — "
                f"STRONG indicator this is a cryptominer module"
            ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 19b: Cryptominer Export Names
    # ------------------------------------------------------------------ #
    def _test_cryptominer_exports(self, fp: str, data: bytes) -> List[Finding]:
        """
        Extract readable strings from the WASM binary and check for
        mining-related function export names.
        """
        findings = []

        # Extract printable ASCII strings (length >= 4)
        strings = re.findall(b'[\x20-\x7e]{4,}', data)
        decoded_strings = [s.decode('ascii') for s in strings]

        mining_matches = []
        for s in decoded_strings:
            s_lower = s.lower()
            for name in self.MINER_EXPORT_NAMES:
                if name in s_lower:
                    mining_matches.append((s, name))
                    break

        for full_string, matched_name in mining_matches:
            findings.append(Finding(
                "wasm_cryptominer", "MEDIUM", fp, 0,
                full_string[:200],
                f"Mining-related string found: matches '{matched_name}'"
            ))

        if len(mining_matches) >= 3:
            names = [m[1] for m in mining_matches[:10]]
            findings.append(Finding(
                "wasm_cryptominer", "HIGH", fp, 0,
                ", ".join(names),
                f"Found {len(mining_matches)} mining-related export/function names"
            ))

        return findings

    # ------------------------------------------------------------------ #
    # TEST 19c: Known File Hash
    # ------------------------------------------------------------------ #
    def _test_file_hash(self, fp: str, data: bytes) -> List[Finding]:
        """Check file hash against known cryptominer WASM modules."""
        findings = []
        if self.KNOWN_MINER_HASHES:
            import hashlib
            file_hash = hashlib.sha256(data).hexdigest()
            if file_hash in self.KNOWN_MINER_HASHES:
                findings.append(Finding(
                    "wasm_cryptominer", "CRITICAL", fp, 0,
                    f"SHA256: {file_hash}",
                    "WASM file hash matches KNOWN cryptominer module"
                ))
        return findings

    # ------------------------------------------------------------------ #
    # TEST 19d: Suspicious Size Heuristic
    # ------------------------------------------------------------------ #
    def _test_suspicious_size(self, fp: str, data: bytes) -> List[Finding]:
        """Size heuristic removed — only MEDIUM+ findings kept."""
        return []
