#!/usr/bin/env python3
import socket
import threading
import json
import base64
from pathlib import Path

# cryptography library
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

SERVER_HOST = "127.0.0.1"  # change to your server IP in LAN
SERVER_PORT = 5000

KEYS_DIR = Path(".keys")
KEY_BITS = 2048

def send_json(sock, obj):
    data = json.dumps(obj, ensure_ascii=False).encode() + b"\n"
    sock.sendall(data)

def recv_lines(sock):
    return sock.makefile("r", encoding="utf-8", newline="\n")

def pem_public_key(pubkey):
    return pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

def pem_private_key(privkey):
    return privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # keep simple for demo
    ).decode()

def load_or_create_keys(username: str):
    KEYS_DIR.mkdir(exist_ok=True)
    priv_path = KEYS_DIR / f"{username}_private.pem"
    pub_path = KEYS_DIR / f"{username}_public.pem"

    if priv_path.exists() and pub_path.exists():
        private_key = serialization.load_pem_private_key(
            priv_path.read_bytes(), password=None, backend=default_backend()
        )
        public_key = serialization.load_pem_public_key(pub_path.read_bytes(), backend=default_backend())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS, backend=default_backend())
        public_key = private_key.public_key()
        priv_path.write_text(pem_private_key(private_key), encoding="utf-8")
        pub_path.write_text(pem_public_key(public_key), encoding="utf-8")

    return private_key, public_key

def fingerprint_of_public_pem(pem: str):
    # Simple SHA-256 of the DER bytes
    pub = serialization.load_pem_public_key(pem.encode(), backend=default_backend())
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    fp = digest.finalize()
    # return shortened hex
    return ":".join(f"{b:02x}" for b in fp[:8])

class Keyring:
    def __init__(self):
        self.map = {}  # username -> {"public_pem": str, "fingerprint": str}

    def set(self, username, public_pem, fingerprint):
        self.map[username] = {"public_pem": public_pem, "fingerprint": fingerprint}

    def get_public_key(self, username):
        entry = self.map.get(username)
        if not entry:
            return None
        return serialization.load_pem_public_key(entry["public_pem"].encode(), backend=default_backend())

    def ensure(self, sock, username):
        if username in self.map:
            return True
        send_json(sock, {"type": "GET_PUBLIC_KEY", "username": username})
        return False  # caller should retry once a PUBLIC_KEY arrives

def encrypt_for(pubkey, plaintext: str) -> bytes:
    return pubkey.encrypt(
        plaintext.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

def decrypt_with(private_key, ciphertext: bytes) -> str:
    pt = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return pt.decode()

def main():
    username = input("Tu username: ").strip()
    private_key, public_key = load_or_create_keys(username)
    my_public_pem = pem_public_key(public_key)
    my_fingerprint = fingerprint_of_public_pem(my_public_pem)

    keyring = Keyring()

    print(f"[{username}] fingerprint: {my_fingerprint}")
    print(f"[client] conectando a {SERVER_HOST}:{SERVER_PORT} ...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    # REGISTER
    send_json(sock, {
        "type": "REGISTER",
        "username": username,
        "public_key": my_public_pem,
        "fingerprint": my_fingerprint,
    })

    # Reader thread
    def reader():
        f = recv_lines(sock)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue

            t = msg.get("type")
            if t == "REGISTERED":
                roster = msg.get("roster", [])
                if roster:
                    print("[server] usuarios conectados:",
                          ", ".join(f'{r['"username"']}({r['"fingerprint"']})' for r in roster))
                else:
                    print("[server] no hay otros usuarios conectados.")
            elif t == "PUBLIC_KEY":
                if msg.get("found"):
                    keyring.set(msg["username"], msg["public_key"], msg["fingerprint"])
                    print(f"[server] clave pública de {msg['username']} guardada (fp {msg['fingerprint']}).")
                else:
                    print(f"[server] {msg['username']} no encontrado.")
            elif t == "ROOM_MSG":
                print(f"[sala] {msg.get('text','')}")
            elif t == "PM":
                sender = msg.get("from")
                ct_b64 = msg.get("ciphertext_b64")
                if not ct_b64:
                    continue
                try:
                    ciphertext = base64.b64decode(ct_b64)
                    plaintext = decrypt_with(private_key, ciphertext)
                    print(f"[PM de {sender}] {plaintext}")
                except Exception as e:
                    print(f"[PM de {sender}] <error al descifrar: {e}>")
            elif t == "ERROR":
                print(f"[error] {msg.get('error')} -> {msg}")
            else:
                print(f"[?] {msg}")

    threading.Thread(target=reader, daemon=True).start()

    # Simple CLI:
    print("Comandos:")
    print("  /pm <usuario> <texto>    Enviar mensaje privado cifrado (RSA-OAEP)")
    print("  /say <texto>             Mensaje a la sala (claro)")
    print("  /quit                    Salir")

    try:
        while True:
            line = input("> ").strip()
            if not line:
                continue
            if line.lower() in ("/quit", "salir", "exit"):
                break
            if line.startswith("/pm "):
                # parse "/pm user message..."
                try:
                    _, to, *rest = line.split()
                    text = " ".join(rest)
                except ValueError:
                    print("uso: /pm <usuario> <texto>")
                    continue

                # ensure we have recipient key (request once if missing)
                if not keyring.ensure(sock, to):
                    print(f"[info] pidiendo clave pública de {to}... vuelve a intentar cuando llegue.")
                    continue

                pubkey = keyring.get_public_key(to)
                if not pubkey:
                    print(f"[info] aún no tengo la clave de {to}.")
                    continue

                ciphertext = encrypt_for(pubkey, text)
                send_json(sock, {
                    "type": "PM",
                    "from": username,
                    "to": to,
                    "alg": "RSA-OAEP-SHA256",
                    "ciphertext_b64": base64.b64encode(ciphertext).decode(),
                })
            elif line.startswith("/say "):
                text = line[len("/say "):]
                send_json(sock, {"type": "ROOM_SAY", "text": f"{username}: {text}"})
            else:
                print("Comando no reconocido.")
    finally:
        try:
            sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
