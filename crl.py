"""Certificate Revocation List (CRL) management.

The root CA signs a CRL that lists revoked leaf certificates. The validator
and the TLS server both load this CRL to reject revoked certificates, which
replaces the previous plaintext ``revoked.txt`` approach.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from config import (
    CA_CERT,
    CA_CRL,
    CA_KEY,
    REVOKED_JSON,
    ca_password_bytes,
    get_ca_passphrase,
)


def load_ca(passphrase: Optional[str] = None):
    """Load the CA private key (decrypting it with the passphrase) and cert."""
    pw = ca_password_bytes() if passphrase is None else (
        passphrase.encode() if passphrase else None
    )
    key = serialization.load_pem_private_key(CA_KEY.read_bytes(), password=pw)
    cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())
    return key, cert


def _load_revoked() -> List[dict]:
    if not REVOKED_JSON.exists():
        return []
    return json.loads(REVOKED_JSON.read_text())


def generate_crl(
    passphrase: Optional[str] = None,
    ca_key=None,
    ca_cert=None,
) -> str:
    """(Re)build the CRL from the revoked list and sign it with the CA."""
    if ca_key is None or ca_cert is None:
        ca_key, ca_cert = load_ca(passphrase)

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=30))
        .add_extension(x509.CRLNumber(1), critical=False)
    )

    for entry in _load_revoked():
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(int(entry["serial"]))
            .revocation_date(datetime.fromisoformat(entry["revoked_at"]))
            .add_extension(
                x509.CRLReason(getattr(x509.ReasonFlags, entry.get("reason", "unspecified"))),
                critical=False,
            )
            .build()
        )

    crl = builder.sign(ca_key, hashes.SHA256())
    CA_CRL.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return str(CA_CRL)


def revoke_certificate(
    serial_number: int,
    reason=x509.ReasonFlags.unspecified,
    passphrase: Optional[str] = None,
) -> bool:
    """Add a serial number to the revoked list and re-sign the CRL."""
    serial_number = int(serial_number)
    revoked = _load_revoked()
    if any(int(e["serial"]) == serial_number for e in revoked):
        return False

    revoked.append(
        {
            "serial": serial_number,
            "revoked_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason.name,
        }
    )
    REVOKED_JSON.write_text(json.dumps(revoked, indent=2))
    generate_crl(passphrase)
    return True
