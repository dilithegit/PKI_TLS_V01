# Mini PKI + TLS Simulator

A small, self-contained Public Key Infrastructure demo written in Python using
the [`cryptography`](https://cryptography.io) library and a Tkinter GUI. It
issues a root CA, signs server and client certificates, validates them (with
CRL revocation checks), and runs mutually-authenticated TLS (mTLS) between a
client and server.

## What it does

- **`ca.py`** — creates a 4096-bit self-signed root CA. The CA private key is
  **encrypted at rest** with a passphrase, and the CA publishes a CRL.
- **`cert_generator.py`** — issues a **server** certificate (SANs for
  `localhost` + `127.0.0.1`, `serverAuth` EKU) and a **client** certificate
  (`clientAuth` EKU) for mutual TLS. Both are signed by the CA and carry a CRL
  distribution point.
- **`crl.py`** — builds/rebuilds the Certificate Revocation List and revokes
  certificates by serial number.
- **`validator.py`** — verifies issuer, validity window (timezone-aware),
  signature, **CRL revocation**, and Extended Key Usage.
- **`tls_server.py` / `tls_client.py`** — real TLS 1.2+ sockets. The server
  requires and CRL-checks a client certificate; the client verifies the server
  hostname and presents its own certificate.
- **`app.py`** — the GUI: generate the CA/certs, validate, revoke, and start
  the mTLS server/client.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

## Using the GUI

1. Enter a **CA passphrase** (it encrypts all generated keys — keep it safe).
2. Click **Generate CA**, then **Server Cert** and **Client Cert**.
3. Click **Validate** to run the full chain + CRL check.
4. **Start Server**, then **Run Client** to perform an mTLS handshake.
5. **Revoke Server** then **Validate** again to see revocation rejected.

You can also run pieces from the command line, e.g.:

```bash
set PKI_CA_PASSPHRASE=yourpass
python -c "from ca import create_ca; create_ca()"
python -m validator
python -m tls_server   # in one terminal
python -m tls_client   # in another
```

## Security notes

This is an **educational simulator**, not production PKI. Keys are RSA and
encrypted only with a passphrase; there is no HSM, no OCSP, no intermediate CA
path, and the CRL is a local file. Do not use the generated material for real
trust.
