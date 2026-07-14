"""Mutually-authenticated TLS server.

Hardening compared to the original:
- requires TLS 1.2+ and a restricted cipher suite,
- requires (and CRL-checks) a client certificate (mTLS),
- decrypts its own encrypted key using the CA passphrase,
- handles client errors and shuts down cleanly via an event.
"""
from __future__ import annotations

import socket
import ssl
import threading
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from config import (
    CA_CERT,
    CIPHERS,
    HOST,
    PORT,
    SERVER_CERT,
    SERVER_KEY,
    TLS_MIN_VERSION,
    ca_password_bytes,
)
from validator import validate_cert_obj

SERVER_MESSAGE = b"Hello from secure server!"


def start_tls_server(stop_event: Optional[threading.Event] = None) -> None:
    if stop_event is None:
        stop_event = threading.Event()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = TLS_MIN_VERSION
    context.set_ciphers(CIPHERS)

    pw = ca_password_bytes()
    context.load_cert_chain(
        certfile=str(SERVER_CERT),
        keyfile=str(SERVER_KEY),
        password=pw,
    )

    # Require and verify the client certificate against our CA. CRL revocation
    # is enforced after the handshake via validate_cert_obj (this Python build
    # has no crlfile support in ssl).
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(CA_CERT))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    tls_server = context.wrap_socket(server_socket, server_side=True)
    print(f"TLS server (mTLS) listening on {HOST}:{PORT}")

    try:
        while not stop_event.is_set():
            try:
                client_socket, addr = tls_server.accept()
            except ssl.SSLError as e:
                print(f"TLS handshake failed from {addr}: {e}")
                continue

            with client_socket:
                der = client_socket.getpeercert(binary_form=True)
                client_cert = x509.load_der_x509_certificate(der)
                ok, msg = validate_cert_obj(client_cert)
                if not ok:
                    print(f"Rejecting client {addr}: {msg}")
                    client_socket.close()
                    continue

                try:
                    eku = client_cert.extensions.get_extension_for_class(
                        x509.ExtendedKeyUsage
                    ).value
                    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                        raise ValueError("missing client-auth EKU")
                except Exception:
                    print(f"Rejecting client {addr}: not a client certificate")
                    client_socket.close()
                    continue

                peer = client_socket.getpeercert()
                print(f"Authenticated client: {peer.get('subject')}")
                data = client_socket.recv(1024)
                if data:
                    print(f"Client says: {data.decode(errors='replace')}")
                    client_socket.sendall(SERVER_MESSAGE)
    finally:
        tls_server.close()
        print("TLS server stopped.")


if __name__ == "__main__":
    start_tls_server()
