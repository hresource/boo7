# b007.py
import os
import json
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import threading
import asyncio
import requests
import hashlib
from datetime import datetime
import rsa

# === LOAD CONFIG ===
def load_config():
    # Always find config.json in the same folder as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.json')

    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

config = load_config()
print(config)  # Optional: just to verify it loaded

# === DB INIT ===
DB_CONN = sqlite3.connect('b007.db', check_same_thread=False)
c = DB_CONN.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY, phone TEXT, status TEXT, country TEXT, activated_at TEXT
)''')
c.execute('''CREATE TABLE IF NOT EXISTS intel (
    user_id INTEGER, username TEXT, phone TEXT, source TEXT, scraped_at TEXT
)''')
DB_CONN.commit()

# === LICENSE VALIDATION ===
def get_machine_id():
    return hashlib.sha256(os.environ.get("COMPUTERNAME", "default").encode()).hexdigest()[:16]

def validate_license(license_key: str):
    try:
        with open("public_key.pem", "rb") as f:
            pubkey = rsa.PublicKey.load_pkcs1(f.read())
        decoded = base64.b64decode(license_key)
        payload, signature = decoded.split(b"|")
        rsa.verify(payload, signature, pubkey)
        data = json.loads(payload.decode())
        expiry = datetime.fromisoformat(data["expiry"])
        if datetime.now() > expiry:
            return {"valid": False, "reason": "EXPIRED"}
        if data.get("machine") != get_machine_id():
            return {"valid": False, "reason": "MACHINE_MISMATCH"}
        return {"valid": True, "data": data}
    except:
        return {"valid": False, "reason": "INVALID"}

def validate_license_full(license_key: str):
    local = validate_license(license_key)
    if not local["valid"]:
        return local

    data = local["data"]
    try:
        key_hash = hashlib.sha256(license_key.encode()).hexdigest()
        payload = {
            'key_hash': key_hash,
            'machine_id': get_machine_id(),
            'expiry': data["expiry"]
        }
        resp = requests.post(
            "https://b007-license-server.vercel.app/api/validate",
            json=payload,
            timeout=10
        )
        server = resp.json()
        if not server.get('valid'):
            return {"valid": False, "reason": server.get('reason', 'UNKNOWN')}
    except:
        pass  # Offline = allow
    return local

# === GUI ===
class B007App:
    def __init__(self, root):
        self.root = root
        self.root.title("B 007 – Intelligence Division")
        self.root.geometry("1100x750")
        self.root.configure(bg="#0a0a0a")
        self.setup_ui()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TButton", background="#1a1a1a", foreground="#00ff00", font=("Consolas", 10, "bold"))
        style.configure("TLabel", background="#0a0a0a", foreground="#00ff41", font=("Consolas", 11))

        tk.Label(self.root, text="B 007", font=("Impact", 32, "bold"), fg="#00ff41", bg="#0a0a0a").pack(pady=15)
        tk.Label(self.root, text="TELEGRAM INTELLIGENCE DIVISION", font=("Courier", 10), fg="#00ff41", bg="#0a0a0a").pack()

        panel = ttk.Frame(self.root); panel.pack(pady=20, padx=30, fill="x")
        ttk.Label(panel, text="TARGET:").grid(row=0, column=0, sticky="w")
        self.target = ttk.Entry(panel, width=60); self.target.grid(row=0, column=1, padx=10)

        btns = ttk.Frame(self.root); btns.pack(pady=15)
        ttk.Button(btns, text="ACTIVATE 10", command=self.activate).pack(side="left", padx=8)
        ttk.Button(btns, text="EXTRACT INTEL", command=self.extract).pack(side="left", padx=8)
        ttk.Button(btns, text="LAUNCH HQ", command=lambda: os.system("streamlit run saas_dashboard.py")).pack(side="left", padx=8)

        self.log = scrolledtext.ScrolledText(self.root, bg="#000", fg="#00ff41", font=("Courier", 10), height=22)
        self.log.pack(fill="both", expand=True, padx=20, pady=10)
        self.log_insert("SYSTEM ONLINE")

    def log_insert(self, msg):
        self.log.insert(tk.END, f"> {msg}\n")
        self.log.see(tk.END)

    def activate(self):
        threading.Thread(target=lambda: [self.log_insert("ACTIVATED") for _ in range(10)], daemon=True).start()

    def extract(self):
        threading.Thread(target=lambda: self.log_insert(f"EXTRACTED FROM {self.target.get()}"), daemon=True).start()

# === MAIN ===
if __name__ == "__main__":
    license_key = simpledialog.askstring("B 007", "Enter License Key:", show="*")
    if not license_key or not validate_license_full(license_key)["valid"]:
        messagebox.showerror("ACCESS DENIED", "Invalid or revoked license.")
        exit(1)
    root = tk.Tk()
    app = B007App(root)
    root.mainloop()