"""Tkinter GUI for the Mini PKI + TLS simulator.

Improvements over the original:
- a passphrase field so the CA/leaf keys are encrypted at rest,
- one-click generation of the CA, server cert and client (mTLS) cert,
- live certificate info + color-coded validation result,
- start/stop controls for the server and a revoke button,
- an activity log.
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

import config
from ca import create_ca
from cert_generator import create_server_cert, create_client_cert
from crl import revoke_certificate
from tls_client import start_tls_client
from tls_server import start_tls_server
from validator import validate_cert

server_thread: threading.Thread | None = None
server_stop = threading.Event()


# -----------------------------
# Helpers
# -----------------------------
def log(message: str) -> None:
    log_box.insert(tk.END, message + "\n")
    log_box.see(tk.END)


def apply_passphrase() -> None:
    config.set_ca_passphrase(passphrase_var.get() or None)


def run_task(label: str, fn) -> None:
    try:
        fn()
        log(f"[+] {label} succeeded.")
    except Exception as e:  # noqa: BLE001
        log(f"[!] {label} failed: {e}")
        messagebox.showerror(label, str(e))


def refresh_status() -> None:
    lines = []
    for name, path in [
        ("CA key", config.CA_KEY),
        ("CA cert", config.CA_CERT),
        ("CA CRL", config.CA_CRL),
        ("Server cert", config.SERVER_CERT),
        ("Client cert", config.CLIENT_CERT),
    ]:
        lines.append(f"{name:<12}: {'present' if path.exists() else 'missing'}")
    info_box.config(text="\n".join(lines))


def do_validate() -> None:
    ok, msg = validate_cert()
    result_var.set(msg)
    result_label.config(fg="#00ff88" if ok else "#ff5555")
    log(f"[{'✓' if ok else '✗'}] Validation: {msg}")


# -----------------------------
# Actions
# -----------------------------
def generate_ca():
    apply_passphrase()
    if not passphrase_var.get():
        messagebox.showwarning("Passphrase", "Set a CA passphrase first (it encrypts the keys).")
        return
    run_task("Create CA", create_ca)
    refresh_status()


def generate_server():
    apply_passphrase()
    run_task("Create server cert", create_server_cert)
    refresh_status()


def generate_client():
    apply_passphrase()
    run_task("Create client cert", create_client_cert)
    refresh_status()


def revoke_server():
    apply_passphrase()
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(config.SERVER_CERT.read_bytes())
        revoked = revoke_certificate(cert.serial_number)
        log(f"[{'✓' if revoked else 'i'}] Server cert {'revoked' if revoked else 'already revoked'}.")
    except Exception as e:  # noqa: BLE001
        log(f"[!] Revoke failed: {e}")
        messagebox.showerror("Revoke", str(e))


def start_server():
    global server_thread
    if server_thread and server_thread.is_alive():
        return
    server_stop.clear()
    server_thread = threading.Thread(
        target=start_tls_server, args=(server_stop,), daemon=True
    )
    server_thread.start()
    status_var.set("TLS server running (mTLS)")
    log("[*] TLS server started.")


def stop_server():
    server_stop.set()
    status_var.set("TLS server stopped")
    log("[*] TLS server stopping...")


def run_client():
    apply_passphrase()
    threading.Thread(target=lambda: run_task("TLS client", start_tls_client), daemon=True).start()


# -----------------------------
# Main window
# -----------------------------
root = tk.Tk()
root.title("Mini PKI + TLS Simulator")
root.geometry("760x640")
root.config(bg="#1e1e2f")

passphrase_var = tk.StringVar()
result_var = tk.StringVar(value="Not validated")
status_var = tk.StringVar(value="System ready")

header = tk.Label(
    root, text="🔐 Mini PKI + TLS Simulator", font=("Arial", 20, "bold"),
    bg="#1e1e2f", fg="white",
)
header.pack(pady=(14, 4))
sub = tk.Label(
    root, text="Certificates · Trust Chain · Mutual TLS",
    font=("Arial", 11), bg="#1e1e2f", fg="#bbbbbb",
)
sub.pack()

# Passphrase row
pf = tk.Frame(root, bg="#1e1e2f")
pf.pack(pady=8)
tk.Label(pf, text="CA passphrase:", bg="#1e1e2f", fg="white", font=("Arial", 10)).pack(side=tk.LEFT)
tk.Entry(pf, textvariable=passphrase_var, show="*", width=28, font=("Consolas", 10)).pack(side=tk.LEFT, padx=6)

# Button grid
btn_frame = tk.Frame(root, bg="#1e1e2f")
btn_frame.pack(pady=6)


def make_button(text, cmd, col=0, row=0):
    b = tk.Button(
        btn_frame, text=text, command=cmd, width=22, height=2,
        font=("Arial", 10, "bold"), bg="#3a86ff", fg="white",
        relief="flat", cursor="hand2",
    )
    b.grid(row=row, column=col, padx=6, pady=5)


make_button("1. Generate CA", generate_ca, 0, 0)
make_button("2. Server Cert", generate_server, 1, 0)
make_button("3. Client Cert", generate_client, 2, 0)
make_button("Validate", do_validate, 0, 1)
make_button("Revoke Server", revoke_server, 1, 1)
make_button("Start Server", start_server, 0, 2)
make_button("Stop Server", stop_server, 1, 2)
make_button("Run Client", run_client, 2, 2)

# Info + result
mid = tk.Frame(root, bg="#1e1e2f")
mid.pack(pady=6, fill=tk.X, padx=20)
tk.Label(mid, text="Material", bg="#1e1e2f", fg="white", font=("Arial", 11, "bold")).pack(anchor="w")
info_box = tk.Label(
    mid, text="", bg="#2b2b3d", fg="#cccccc", font=("Consolas", 9),
    justify=tk.LEFT, anchor="w", padx=8, pady=6,
)
info_box.pack(fill=tk.X, pady=(2, 6))

tk.Label(mid, text="Validation", bg="#1e1e2f", fg="white", font=("Arial", 11, "bold")).pack(anchor="w")
result_label = tk.Label(
    mid, textvariable=result_var, bg="#2b2b3d", fg="#00ff88",
    font=("Consolas", 11, "bold"), anchor="w", padx=8, pady=6,
)
result_label.pack(fill=tk.X, pady=(2, 4))

# Log
tk.Label(root, text="Activity Log", bg="#1e1e2f", fg="white", font=("Arial", 11, "bold")).pack()
log_box = scrolledtext.ScrolledText(
    root, width=88, height=12, bg="#2b2b3d", fg="#00ff88", font=("Consolas", 9)
)
log_box.pack(pady=(4, 8), padx=20)

# Status bar
tk.Label(
    root, textvariable=status_var, bd=1, relief="sunken", anchor="w",
    bg="#111827", fg="white", font=("Arial", 10),
).pack(side=tk.BOTTOM, fill=tk.X)

refresh_status()
root.mainloop()
