"""Leaf certificate issuance: server (for TLS) and client (for mTLS).

Both certificates are signed by the root CA, carry Subject Alternative Names
(replacing the deprecated CN-only identity), point at the CA's CRL, and are
restricted by Extended Key Usage to their role.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from config import (
    CA_CERT,
    CA_CRL,
    CA_KEY,
    CERTS_DIR,
    CLIENT_CERT,
    CLIENT_KEY,
    SERVER_CERT,
    SERVER_CSR,
    SERVER_KEY,
    ca_password_bytes,
)
from crl import load_ca


def _build_leaf(
    common_name: str,
    organization: str,
    sans: List[x509.GeneralName],
    eku,
    passphrase: Optional[str],
) -> None:
    CERTS_DIR.mkdir(exist_ok=True)

    if not CA_KEY.exists() or not CA_CERT.exists():
        raise FileNotFoundError(
            "CA key/cert not found. Generate the CA first."
        )

    pw = ca_password_bytes() if passphrase is None else (
        passphrase.encode() if passphrase else None
    )
    enc_algo = (
        serialization.BestAvailableEncryption(pw)
        if pw
        else serialization.NoEncryption()
    )

    ca_key, ca_cert = load_ca(passphrase)

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ca_key, ca_cert, leaf_key, enc_algo


def create_server_cert(passphrase: Optional[str] = None) -> None:
    ca_key, ca_cert, server_key, enc_algo = _build_leaf(
        "localhost",
        "Mini PKI Server",
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ],
        ExtendedKeyUsageOID.SERVER_AUTH,
        passphrase,
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Nairobi"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Nairobi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini PKI Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    SERVER_KEY.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc_algo,
        )
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(server_key, hashes.SHA256())
    )
    SERVER_CSR.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    now = datetime.now(timezone.utc)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
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

    SERVER_CERT.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    print("Server certificate signed by CA.")


def create_client_cert(passphrase: Optional[str] = None) -> None:
    ca_key, ca_cert, client_key, enc_algo = _build_leaf(
        "mini-client",
        "Mini PKI Client",
        [x509.DNSName("mini-client")],
        ExtendedKeyUsageOID.CLIENT_AUTH,
        passphrase,
    )

    CLIENT_KEY.write_bytes(
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc_algo,
        )
    )

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini PKI Client"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mini-client"),
        ]
    )

    now = datetime.now(timezone.utc)
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
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

    CLIENT_CERT.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    print("Client certificate signed by CA.")
