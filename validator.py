from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime


def validate_cert():
    try:
        # Load server certificate
        with open("certs/server_cert.pem", "rb") as f:
            server_cert = x509.load_pem_x509_certificate(f.read())

        # Load CA certificate
        with open("certs/ca_cert.pem", "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # ----------------------------------------
        # 1. CHECK ISSUER
        # ----------------------------------------
        if server_cert.issuer != ca_cert.subject:
            return "Certificate Invalid: Wrong issuer"

        # ----------------------------------------
        # 2. CHECK EXPIRY
        # ----------------------------------------
        current_time = datetime.utcnow()

        if current_time < server_cert.not_valid_before:
            return "Certificate Invalid: Not yet valid"

        if current_time > server_cert.not_valid_after:
            return "Certificate Expired"

        # ----------------------------------------
        # 3. CHECK SIGNATURE
        # Verify server certificate was signed by CA
        # ----------------------------------------
        try:
            ca_cert.public_key().verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                server_cert.signature_hash_algorithm,
            )
        except Exception:
            return "Certificate Invalid: Signature verification failed"

        # ----------------------------------------
        # 4. CHECK REVOCATION
        # ----------------------------------------
        serial_number = str(server_cert.serial_number)

        try:
            with open("revoked.txt", "r") as f:
                revoked_serials = f.read().splitlines()

            if serial_number in revoked_serials:
                return "Certificate Revoked"

        except FileNotFoundError:
            # If file doesn't exist, assume no revoked certs
            pass

        # ----------------------------------------
        # EVERYTHING PASSED
        # ----------------------------------------
        return "Certificate Valid"

    except FileNotFoundError:
        return "Certificate file not found"

    except Exception as e:
        return f"Validation Error: {str(e)}"