import socket
import ssl


HOST = "127.0.0.1"
PORT = 8443


def start_tls_client():
    # Create SSL context
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH
    )

    # Load trusted CA certificate
    context.load_verify_locations("certs/ca_cert.pem")

    # Require certificate validation
    context.verify_mode = ssl.CERT_REQUIRED

    # Create normal socket
    client_socket = socket.create_connection((HOST, PORT))

    # Wrap socket with TLS
    tls_client = context.wrap_socket(
        client_socket,
        server_hostname="localhost"
    )

    print("TLS handshake successful!")
    print("Server certificate verified.")

    # Send encrypted message
    tls_client.send(b"Hello secure server!")

    # Receive encrypted reply
    data = tls_client.recv(1024)
    print("Server says:", data.decode())

    tls_client.close()


if __name__ == "__main__":
    start_tls_client()