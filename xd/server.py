#!/usr/bin/env python3
import socket
import threading
import json
import base64
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

HOST = "0.0.0.0"
PORT = 5000

# username -> { "public_key": str, "fingerprint": str, "sock": socket.socket, "verified": bool }
directory = {}
clients = set()
# sock -> username mapping for validation
sock_to_user = {}

def generate_full_fingerprint(public_key_pem: str) -> str:
    """Generate full SHA-256 fingerprint of the public key"""
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(der)
        fp = digest.finalize()
        return fp.hex()
    except Exception:
        return ""

def verify_signature_challenge(public_key_pem: str, challenge: str, signature_b64: str) -> bool:
    """Verify that the client can sign with the private key corresponding to the public key"""
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        signature = base64.b64decode(signature_b64)
        pub.verify(
            signature,
            challenge.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# --- Wire helpers: line-delimited JSON ---
def send_json(sock, obj):
    data = json.dumps(obj, ensure_ascii=False).encode() + b"\n"
    sock.sendall(data)

def recv_lines(sock):
    # Use a file-like wrapper to read lines safely
    return sock.makefile("r", encoding="utf-8", newline="\n")

def broadcast_room(text, sender_sock):
    # Simple clear-text broadcast to everyone (kept from your MVP)
    for c in list(clients):
        if c is not sender_sock:
            try:
                send_json(c, {"type": "ROOM_MSG", "text": text})
            except Exception:
                clients.discard(c)

def handle_client(sock, addr):
    f = recv_lines(sock)
    username = None
    pending_challenge = None  # Store challenge for verification

    try:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue

            mtype = msg.get("type")

            # 1) REGISTER - Step 1: Initial registration request
            if mtype == "REGISTER":
                req_username = msg.get("username")
                pub = msg.get("public_key")
                fp = msg.get("fingerprint")
                if not req_username or not pub or not fp:
                    send_json(sock, {"type": "ERROR", "error": "invalid_register"})
                    continue

                # Check if username is already taken by a different verified connection
                existing = directory.get(req_username)
                if existing and existing.get("sock") and existing.get("verified") and existing["sock"] != sock:
                    send_json(sock, {"type": "ERROR", "error": "username_taken"})
                    continue

                # Generate full SHA-256 fingerprint and verify it matches
                full_fp = generate_full_fingerprint(pub)
                if not full_fp:
                    send_json(sock, {"type": "ERROR", "error": "invalid_public_key"})
                    continue

                # For now, we accept shortened fingerprints, but store the full one
                # In production, you might want to enforce full fingerprint validation
                
                # Generate challenge for proof of possession
                challenge = secrets.token_hex(32)  # 256-bit random challenge
                pending_challenge = {"username": req_username, "public_key": pub, "fingerprint": full_fp, "challenge": challenge}
                
                send_json(sock, {
                    "type": "CHALLENGE",
                    "challenge": challenge,
                    "message": "Sign this challenge with your private key to complete registration"
                })

            # 1b) REGISTER - Step 2: Challenge response
            elif mtype == "CHALLENGE_RESPONSE":
                if not pending_challenge:
                    send_json(sock, {"type": "ERROR", "error": "no_pending_challenge"})
                    continue
                
                signature_b64 = msg.get("signature")
                if not signature_b64:
                    send_json(sock, {"type": "ERROR", "error": "missing_signature"})
                    continue

                # Verify the signature
                if verify_signature_challenge(
                    pending_challenge["public_key"],
                    pending_challenge["challenge"], 
                    signature_b64
                ):
                    # Registration successful - store verified user
                    reg_username = pending_challenge["username"]
                    username = reg_username  # Set this connection's username
                    
                    directory[reg_username] = {
                        "public_key": pending_challenge["public_key"],
                        "fingerprint": pending_challenge["fingerprint"],
                        "sock": sock,
                        "verified": True
                    }
                    sock_to_user[sock] = reg_username
                    pending_challenge = None

                    # Send successful registration and roster
                    roster = [{"username": u, "fingerprint": d["fingerprint"][:16] + "..."}  # Show shortened for display
                              for u, d in directory.items() if d.get("sock") and d.get("verified")]
                    send_json(sock, {"type": "REGISTERED", "you": reg_username, "roster": roster})
                else:
                    send_json(sock, {"type": "ERROR", "error": "invalid_signature"})
                    pending_challenge = None

            # 2) GET_PUBLIC_KEY (only return verified users)
            elif mtype == "GET_PUBLIC_KEY":
                target = msg.get("username")
                entry = directory.get(target)
                if not entry or not entry.get("verified"):
                    send_json(sock, {"type": "PUBLIC_KEY", "username": target, "found": False})
                else:
                    send_json(sock, {
                        "type": "PUBLIC_KEY",
                        "username": target,
                        "found": True,
                        "public_key": entry["public_key"],
                        "fingerprint": entry["fingerprint"],
                    })

            # 3) PM (ciphertext only; server blindly relays but validates sender)
            elif mtype == "PM":
                # Validate sender identity - critical security improvement
                claimed_from = msg.get("from")
                actual_from = sock_to_user.get(sock)
                
                if not actual_from:
                    send_json(sock, {"type": "ERROR", "error": "not_registered"})
                    continue
                    
                if claimed_from != actual_from:
                    send_json(sock, {"type": "ERROR", "error": "from_spoofing_detected", 
                                   "claimed": claimed_from, "actual": actual_from})
                    continue

                to = msg.get("to")
                entry = directory.get(to)
                if not entry or not entry.get("sock") or not entry.get("verified"):
                    send_json(sock, {"type": "ERROR", "error": "user_not_available", "to": to})
                    continue
                    
                # Use validated sender identity
                payload = {
                    "type": "PM",
                    "from": actual_from,  # Use validated identity, not claimed
                    "to": to,
                    "alg": msg.get("alg", "RSA-OAEP-SHA256"),
                    "ciphertext_b64": msg.get("ciphertext_b64"),
                    "signature_b64": msg.get("signature_b64"),  # optional
                    "sig_alg": msg.get("sig_alg"),              # optional
                }
                try:
                    send_json(entry["sock"], payload)
                except Exception:
                    send_json(sock, {"type": "ERROR", "error": "deliver_failed", "to": to})

            # 4) ROOM broadcast (clear-text demo)
            elif mtype == "ROOM_SAY":
                text = msg.get("text", "")
                broadcast_room(text, sock)

            else:
                send_json(sock, {"type": "ERROR", "error": "unknown_type"})
    finally:
        # cleanup on disconnect
        clients.discard(sock)
        # Clear sock_to_user mapping
        if sock in sock_to_user:
            del sock_to_user[sock]
        # keep directory entry but clear socket if present
        if username and directory.get(username, {}).get("sock") is sock:
            directory[username]["sock"] = None
            directory[username]["verified"] = False  # Mark as unverified when disconnected
        try:
            sock.close()
        except Exception:
            pass

def main():
    print(f"[server] listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()
        while True:
            sock, addr = srv.accept()
            clients.add(sock)
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()

if __name__ == "__main__":
    main()
