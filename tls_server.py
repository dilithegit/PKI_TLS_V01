import socket
import ssl


HOST = "127.0.0.1"
PORT = 8443


def start_tls_server():
    # Create normal TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    print(f"TLS Server running on {HOST}:{PORT}")

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Load server certificate and private key
    context.load_cert_chain(
        certfile="certs/server_cert.pem",
        keyfile="certs/server_key.pem"
    )

    # Wrap socket with TLS
    tls_server = context.wrap_socket(server_socket, server_side=True)

    while True:
        client_socket, addr = tls_server.accept()
        print(f"Connection from {addr}")

        # Receive encrypted data
        data = client_socket.recv(1024).decode()
        print(f"Client says: {data}")

        # Send encrypted response
        client_socket.send(b"Hello from secure server!")

        client_socket.close()


if __name__ == "__main__":
    start_tls_server()