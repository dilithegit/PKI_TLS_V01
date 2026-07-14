"""Root Certificate Authority creation.

Generates a 4096-bit self-signed root CA whose private key is encrypted at
rest. The CA is marked with the proper CA extensions and points consumers at
the CRL it maintains.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from config import (
    CA_CERT,
    CA_CRL,
    CA_KEY,
    CERTS_DIR,
    ca_password_bytes,
)
from crl import generate_crl


def create_ca(passphrase: Optional[str] = None) -> None:
    CERTS_DIR.mkdir(exist_ok=True)

    pw = ca_password_bytes() if passphrase is None else (
        passphrase.encode() if passphrase else None
    )
    enc_algo = (
        serialization.BestAvailableEncryption(pw)
        if pw
        else serialization.NoEncryption()
    )

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    CA_KEY.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        )
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Nairobi"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Nairobi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini PKI CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Mini Root CA"),
        ]
    )

    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(CA_CRL.as_uri())
                        ],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    CA_CERT.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    # Publish an initial (empty) CRL so validators/servers have something to load.
    generate_crl(ca_key=ca_key, ca_cert=ca_cert)
