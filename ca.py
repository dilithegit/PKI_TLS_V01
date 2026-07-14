from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta
import os


def create_ca():
    # Create certs folder if it doesn't exist
    os.makedirs("certs", exist_ok=True)

    # Generate CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Save CA private key
    with open("certs/ca_key.pem", "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Create self-signed CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "KE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Nairobi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Nairobi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini PKI CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mini Root CA"),
    ])

    # Build CA certificate with proper CA extensions
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))

        # Mark as CA
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )

        # CA Key Usage
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # Subject Key Identifier
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                ca_key.public_key()
            ),
            critical=False
        )

        .sign(ca_key, hashes.SHA256())
    )

    # Save CA certificate
    with open("certs/ca_cert.pem", "wb") as f:
        f.write(
            ca_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            )
        )

    print("CA created successfully.")