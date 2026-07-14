"""Certificate validation against the root CA, including CRL checking.

This replaces the original checks with timezone-aware comparisons and a real
CRL verification step. ``validate_cert`` returns ``(ok, message)`` so the UI
can both show a result and react to success/failure. ``validate_cert_obj``
reuses the same logic for an in-memory certificate (e.g. a peer cert fetched
during a TLS handshake).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from config import CA_CERT, CA_CRL, SERVER_CERT


def _verify_signature(issuer_cert: x509.Certificate, cert: x509.Certificate) -> bool:
    try:
        issuer_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def _check_crl(ca_cert: x509.Certificate, cert: x509.Certificate) -> Tuple[bool, str]:
    """Verify the CRL signature and check whether the cert is revoked."""
    if not CA_CRL.exists():
        return True, "No CRL published (skipping revocation check)"

    crl = x509.load_pem_x509_crl(CA_CRL.read_bytes())
    try:
        ca_cert.public_key().verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            crl.signature_hash_algorithm,
        )
    except Exception:
        return False, "Certificate Invalid: CRL signature verification failed"

    now = datetime.now(timezone.utc)
    if not (crl.last_update_utc <= now <= crl.next_update_utc):
        return False, "Certificate Invalid: CRL is expired/stale"

    if cert.serial_number in {rc.serial_number for rc in crl}:
        return False, "Certificate Revoked"

    return True, "Not revoked"


def validate_cert_obj(cert: x509.Certificate) -> Tuple[bool, str]:
    if not CA_CERT.exists():
        return False, "CA certificate not found"

    ca_cert = x509.load_pem_x509_certificate(CA_CERT.read_bytes())

    if cert.issuer != ca_cert.subject:
        return False, "Certificate Invalid: Wrong issuer"

    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, "Certificate Invalid: Not yet valid"
    if now > cert.not_valid_after_utc:
        return False, "Certificate Expired"

    if not _verify_signature(ca_cert, cert):
        return False, "Certificate Invalid: Signature verification failed"

    ok, msg = _check_crl(ca_cert, cert)
    if not ok:
        return False, msg

    return True, "Certificate Valid"


def validate_cert() -> Tuple[bool, str]:
    if not SERVER_CERT.exists() or not CA_CERT.exists():
        return False, "Certificate file not found"

    server_cert = x509.load_pem_x509_certificate(SERVER_CERT.read_bytes())
    ok, msg = validate_cert_obj(server_cert)
    if not ok:
        return ok, msg

    try:
        eku = server_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            return False, "Certificate Invalid: Missing server-auth EKU"
    except x509.ExtensionNotFound:
        return False, "Certificate Invalid: Missing Extended Key Usage"

    return True, "Certificate Valid"


if __name__ == "__main__":
    ok, msg = validate_cert()
    print(msg)
