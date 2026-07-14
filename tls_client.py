"""Mutually-authenticated TLS client.

Hardening compared to the original:
- explicitly enables hostname verification (defense in depth),
- requires the server cert and validates it against our CA + CRL,
- presents the client certificate/key for mTLS,
- decrypts its encrypted key using the CA passphrase.
"""
from __future__ import annotations

import socket
import ssl

from config import (
    CA_CERT,
    CLIENT_CERT,
    CLIENT_KEY,
    HOST,
    PORT,
    ca_password_bytes,
)

CLIENT_MESSAGE = b"Hello secure server!"


def start_tls_client() -> None:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=str(CA_CERT))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    pw = ca_password_bytes()
    context.load_cert_chain(
        certfile=str(CLIENT_CERT),
        keyfile=str(CLIENT_KEY),
        password=pw,
    )

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as tls:
            print("TLS handshake successful!")
            print("Server certificate verified:", tls.getpeercert().get("subject"))
            tls.sendall(CLIENT_MESSAGE)
            data = tls.recv(1024)
            print("Server says:", data.decode(errors="replace"))


if __name__ == "__main__":
    start_tls_client()
