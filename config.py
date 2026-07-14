"""Central configuration: paths, network settings and the CA passphrase source.

Keeping all filesystem locations in one place removes the duplicated
``os.makedirs("certs")`` calls and hardcoded relative paths that previously
broke when the scripts were run from another working directory.
"""
from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"

CA_KEY = CERTS_DIR / "ca_key.pem"
CA_CERT = CERTS_DIR / "ca_cert.pem"
CA_CRL = CERTS_DIR / "ca.crl.pem"

SERVER_KEY = CERTS_DIR / "server_key.pem"
SERVER_CERT = CERTS_DIR / "server_cert.pem"
SERVER_CSR = CERTS_DIR / "server.csr"

CLIENT_KEY = CERTS_DIR / "client_key.pem"
CLIENT_CERT = CERTS_DIR / "client_cert.pem"

REVOKED_JSON = CERTS_DIR / "revoked.json"

HOST = "127.0.0.1"
PORT = 8443

# In-memory passphrase used by the GUI after the user enters it once.
_CA_PASSPHRASE: Optional[str] = os.environ.get("PKI_CA_PASSPHRASE")


def set_ca_passphrase(passphrase: Optional[str]) -> None:
    """Store the CA passphrase in memory (used by the GUI)."""
    global _CA_PASSPHRASE
    _CA_PASSPHRASE = passphrase


def get_ca_passphrase() -> Optional[str]:
    """Resolve the CA passphrase from env var, then in-memory value."""
    return _CA_PASSPHRASE


def ca_password_bytes() -> Optional[bytes]:
    pw = get_ca_passphrase()
    return pw.encode() if pw else None


# TLS hardening: only allow modern, safe protocols and ciphers.
TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_2
CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256"
)
