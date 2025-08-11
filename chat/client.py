#!/usr/bin/env python3
import socket
import threading
import json
import base64
import time
import secrets
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
    # Full SHA-256 of the DER bytes
    pub = serialization.load_pem_public_key(pem.encode(), backend=default_backend())
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    fp = digest.finalize()
    # return full hex for security, but display shortened version
    return fp.hex()

def fingerprint_display(full_hex: str):
    """Display shortened version of fingerprint for user interface"""
    return ":".join(f"{int(full_hex[i:i+2], 16):02x}" for i in range(0, 16, 2))

def sign_challenge(private_key, challenge: str) -> str:
    """Sign a challenge string with the private key using PSS padding"""
    signature = private_key.sign(
        challenge.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def sign_message(private_key, message_data: str) -> str:
    """Sign message data with the private key using PSS padding"""
    signature = private_key.sign(
        message_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def create_signed_message_data(from_user: str, to_user: str, ciphertext_b64: str, nonce: str, timestamp: float) -> str:
    """Create the canonical message data that gets signed (must match server)"""
    return f"{from_user}|{to_user}|{ciphertext_b64}|{nonce}|{timestamp:.0f}"

def verify_message_signature(public_key, message_data: str, signature_b64: str) -> bool:
    """Verify a message signature"""
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message_data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

class Keyring:
    def __init__(self, username: str):
        self.username = username
        self.map = {}  # username -> {"public_pem": str, "fingerprint": str}
        self.known_keys_file = KEYS_DIR / f"{username}_known_keys.json"
        self.load_known_keys()

    def load_known_keys(self):
        """Load previously known keys from disk (TOFU persistence)"""
        if self.known_keys_file.exists():
            try:
                with open(self.known_keys_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.map = data
                    print(f"[TOFU] Cargadas {len(self.map)} claves conocidas")
            except Exception as e:
                print(f"[TOFU] Error cargando claves conocidas: {e}")

    def save_known_keys(self):
        """Save known keys to disk"""
        KEYS_DIR.mkdir(exist_ok=True)
        try:
            with open(self.known_keys_file, 'w', encoding='utf-8') as f:
                json.dump(self.map, f, indent=2)
        except Exception as e:
            print(f"[TOFU] Error guardando claves: {e}")

    def set(self, username, public_pem, fingerprint):
        """Store a public key with TOFU validation"""
        existing = self.map.get(username)
        if existing:
            if existing["fingerprint"] != fingerprint:
                print(f"⚠️  [TOFU ALERT] ¡La clave de {username} ha cambiado!")
                print(f"   Anterior: {fingerprint_display(existing['fingerprint'])}")
                print(f"   Nueva:    {fingerprint_display(fingerprint)}")
                print(f"   Esto podría indicar un ataque MITM o que {username} cambió su clave.")
                
                response = input(f"¿Aceptar nueva clave para {username}? [s/N]: ").strip().lower()
                if response not in ['s', 'si', 'sí', 'y', 'yes']:
                    print(f"[TOFU] Clave rechazada para {username}")
                    return False
                    
                print(f"[TOFU] Clave actualizada para {username}")
            else:
                print(f"[TOFU] Clave confirmada para {username}")
        else:
            print(f"[TOFU] Nueva clave guardada para {username} (fp: {fingerprint_display(fingerprint)})")

        self.map[username] = {"public_pem": public_pem, "fingerprint": fingerprint}
        self.save_known_keys()
        return True

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

    keyring = Keyring(username)

    print(f"[{username}] fingerprint: {fingerprint_display(my_fingerprint)}")
    print(f"[client] conectando a {SERVER_HOST}:{SERVER_PORT} ...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    # REGISTER
    send_json(sock, {
        "type": "REGISTER",
        "username": username,
        "public_key": my_public_pem,
        "fingerprint": my_fingerprint,  # Now full SHA-256
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
            if t == "CHALLENGE":
                # Handle registration challenge
                challenge = msg.get("challenge")
                if challenge:
                    print("[server] Respondiendo desafío de autenticación...")
                    signature = sign_challenge(private_key, challenge)
                    send_json(sock, {
                        "type": "CHALLENGE_RESPONSE",
                        "signature": signature
                    })
            elif t == "REGISTERED":
                roster = msg.get("roster", [])
                print(f"[server] ✅ Registrado exitosamente como {username}")
                if roster:
                    print("[server] usuarios conectados:")
                    for r in roster:
                        print(f"  - {r['username']} (fp: {r['fingerprint']})")
                else:
                    print("[server] no hay otros usuarios conectados.")
            elif t == "PUBLIC_KEY":
                if msg.get("found"):
                    if keyring.set(msg["username"], msg["public_key"], msg["fingerprint"]):
                        print(f"[server] clave pública de {msg['username']} guardada")
                    else:
                        print(f"[server] clave pública de {msg['username']} rechazada por TOFU")
                else:
                    print(f"[server] {msg['username']} no encontrado.")
            elif t == "ROOM_MSG":
                print(f"[sala] {msg.get('text','')}")
            elif t == "PM":
                sender = msg.get("from")
                ct_b64 = msg.get("ciphertext_b64")
                signature_b64 = msg.get("signature_b64")
                nonce = msg.get("nonce")
                timestamp = msg.get("timestamp")
                verified = msg.get("verified", False)
                
                if not ct_b64:
                    continue
                
                # Verify message integrity if we have signature
                integrity_check = "✅" if verified else "❓"
                if signature_b64 and nonce and timestamp:
                    # Get sender's public key to verify signature
                    sender_pubkey = keyring.get_public_key(sender)
                    if sender_pubkey:
                        message_data = create_signed_message_data(sender, username, ct_b64, nonce, timestamp)
                        if verify_message_signature(sender_pubkey, message_data, signature_b64):
                            integrity_check = "✅ 🔐"
                        else:
                            integrity_check = "❌ 🚨"
                            print(f"⚠️  [SECURITY] Firma inválida del mensaje de {sender}!")
                    else:
                        integrity_check = "❓ 🔑"
                        print(f"⚠️  [SECURITY] No tengo la clave pública de {sender} para verificar")
                
                try:
                    ciphertext = base64.b64decode(ct_b64)
                    plaintext = decrypt_with(private_key, ciphertext)
                    print(f"[PM de {sender}] {integrity_check} {plaintext}")
                except Exception as e:
                    print(f"[PM de {sender}] <error al descifrar: {e}>")
            elif t == "PM_ACK":
                to_user = msg.get("to")
                nonce = msg.get("nonce")
                print(f"[entregado] ✅ Mensaje a {to_user} entregado y verificado por el servidor")
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
                ciphertext_b64 = base64.b64encode(ciphertext).decode()
                
                # Create anti-replay protection
                nonce = secrets.token_hex(16)  # 128-bit nonce
                timestamp = time.time()
                
                # Create signed message data
                message_data = create_signed_message_data(username, to, ciphertext_b64, nonce, timestamp)
                signature_b64 = sign_message(private_key, message_data)
                
                print(f"[enviando] PM a {to} con firma e integridad...")
                send_json(sock, {
                    "type": "PM",
                    "from": username,
                    "to": to,
                    "alg": "RSA-OAEP-SHA256",
                    "ciphertext_b64": ciphertext_b64,
                    "signature_b64": signature_b64,
                    "nonce": nonce,
                    "timestamp": timestamp,
                    "sig_alg": "PSS-SHA256"
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
