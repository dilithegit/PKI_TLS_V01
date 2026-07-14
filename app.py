import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading

from ca import create_ca
from cert_generator import create_server_cert
from validator import validate_cert
from tls_server import start_tls_server
from tls_client import start_tls_client


# -----------------------------
# Functions
# -----------------------------

def log(message):
    log_box.insert(tk.END, message + "\n")
    log_box.see(tk.END)


def generate_ca():
    try:
        create_ca()
        status_var.set("CA Created Successfully")
        log("[+] Certificate Authority created.")
        messagebox.showinfo("Success", "CA created successfully")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def generate_server():
    try:
        create_server_cert()
        status_var.set("Server Certificate Generated")
        log("[+] Server certificate created.")
        messagebox.showinfo("Success", "Server certificate generated")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def validate():
    try:
        result = validate_cert()
        status_var.set(result)
        log(f"[✓] Validation Result: {result}")
        messagebox.showinfo("Validation Result", result)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def run_server():
    try:
        log("[*] Starting TLS Server...")
        threading.Thread(target=start_tls_server, daemon=True).start()
        status_var.set("TLS Server Running")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def run_client():
    try:
        log("[*] Starting TLS Client...")
        threading.Thread(target=start_tls_client, daemon=True).start()
        status_var.set("TLS Client Connected")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# -----------------------------
# Main Window
# -----------------------------

root = tk.Tk()
root.title("Mini PKI + TLS Simulator")
root.geometry("700x550")
root.config(bg="#1e1e2f")

# -----------------------------
# Header
# -----------------------------

header = tk.Label(
    root,
    text="🔐 Mini PKI + TLS Simulator",
    font=("Arial", 22, "bold"),
    bg="#1e1e2f",
    fg="white"
)
header.pack(pady=20)

sub_header = tk.Label(
    root,
    text="Simulating Certificates, Trust Chains & Secure Communication",
    font=("Arial", 11),
    bg="#1e1e2f",
    fg="#bbbbbb"
)
sub_header.pack()

# -----------------------------
# Button Frame
# -----------------------------

button_frame = tk.Frame(root, bg="#1e1e2f")
button_frame.pack(pady=20)


def create_button(text, command):
    return tk.Button(
        button_frame,
        text=text,
        command=command,
        width=25,
        height=2,
        font=("Arial", 11, "bold"),
        bg="#3a86ff",
        fg="white",
        relief="flat",
        cursor="hand2"
    )


create_button("Generate CA", generate_ca).pack(pady=8)
create_button("Generate Server Certificate", generate_server).pack(pady=8)
create_button("Validate Certificate", validate).pack(pady=8)
create_button("Start TLS Server", run_server).pack(pady=8)
create_button("Start TLS Client", run_client).pack(pady=8)

# -----------------------------
# Log Box
# -----------------------------

log_label = tk.Label(
    root,
    text="Activity Log",
    font=("Arial", 14, "bold"),
    bg="#1e1e2f",
    fg="white"
)
log_label.pack(pady=10)

log_box = scrolledtext.ScrolledText(
    root,
    width=75,
    height=12,
    bg="#2b2b3d",
    fg="#00ff88",
    font=("Consolas", 10)
)
log_box.pack(pady=10)

# -----------------------------
# Status Bar
# -----------------------------

status_var = tk.StringVar()
status_var.set("System Ready")

status_bar = tk.Label(
    root,
    textvariable=status_var,
    bd=1,
    relief="sunken",
    anchor="w",
    bg="#111827",
    fg="white",
    font=("Arial", 10)
)
status_bar.pack(side="bottom", fill="x")


root.mainloop()