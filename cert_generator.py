import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta


def create_server_cert():
    # Create certs folder if it doesn't exist
    os.makedirs("certs", exist_ok=True)

    # STEP 1: Generate server private key
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Save server private key
    with open("certs/server_key.pem", "wb") as f:
        f.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    print("Server private key generated.")

    # STEP 2: Create CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "KE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Nairobi"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Nairobi"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini PKI Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
        )
        .sign(server_key, hashes.SHA256())
    )

    # Save CSR
    with open("certs/server.csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("CSR created.")

    # STEP 3: Load CA private key
    with open("certs/ca_key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    # STEP 4: Load CA certificate
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # STEP 5: Sign server certificate with CA
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))

        # This is NOT a CA certificate
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

        # Add server fingerprint
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                csr.public_key()
            ),
            critical=False
        )

        # Link back to CA fingerprint
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False
        )

        # Server key usage permissions
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        # Mark this cert for server authentication
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH
            ]),
            critical=False
        )

        # Sign certificate
        .sign(ca_key, hashes.SHA256())
    )

    # Save signed certificate
    with open("certs/server_cert.pem", "wb") as f:
        f.write(
            server_cert.public_bytes(
                serialization.Encoding.PEM
            )
        )

    print("Server certificate signed by CA.")