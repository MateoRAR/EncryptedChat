#!/usr/bin/env python3
import socket
import threading
import json
import base64
import secrets
import hashlib
import time
from collections import defaultdict, deque
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

# Anti-replay protection
message_nonces = defaultdict(lambda: deque(maxlen=1000))  # username -> recent nonces
NONCE_EXPIRY_SECONDS = 300  # 5 minutes

# Rate limiting
user_message_times = defaultdict(lambda: deque(maxlen=50))  # username -> recent message times
MAX_MESSAGES_PER_MINUTE = 30

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

def verify_message_signature(public_key_pem: str, message_data: str, signature_b64: str) -> bool:
    """Verify message signature to ensure integrity and authenticity"""
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        signature = base64.b64decode(signature_b64)
        pub.verify(
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

def is_replay_attack(username: str, nonce: str, timestamp: float) -> bool:
    """Check if this message is a replay attack"""
    current_time = time.time()
    
    # Check if timestamp is too old
    if current_time - timestamp > NONCE_EXPIRY_SECONDS:
        return True
    
    # Check if timestamp is too far in the future (clock skew tolerance: 30 seconds)
    if timestamp - current_time > 30:
        return True
    
    # Check if nonce was already used
    user_nonces = message_nonces[username]
    if nonce in user_nonces:
        return True
    
    # Add nonce to recent nonces
    user_nonces.append(nonce)
    return False

def check_rate_limit(username: str) -> bool:
    """Check if user is exceeding message rate limits"""
    current_time = time.time()
    user_times = user_message_times[username]
    
    # Remove old timestamps (older than 1 minute)
    while user_times and current_time - user_times[0] > 60:
        user_times.popleft()
    
    # Check if user is sending too many messages
    if len(user_times) >= MAX_MESSAGES_PER_MINUTE:
        return False  # Rate limited
    
    # Add current timestamp
    user_times.append(current_time)
    return True

def create_signed_message_data(from_user: str, to_user: str, ciphertext_b64: str, nonce: str, timestamp: float) -> str:
    """Create the canonical message data that gets signed"""
    return f"{from_user}|{to_user}|{ciphertext_b64}|{nonce}|{timestamp:.0f}"

def load_persistent_directory():
    """Load user directory from disk if it exists"""
    from pathlib import Path
    directory_file = Path("server_directory.json")
    if directory_file.exists():
        try:
            with open(directory_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Only load users without active sockets (reconnection data)
                for username, entry in data.items():
                    if entry.get("fingerprint") and entry.get("public_key"):
                        directory[username] = {
                            "public_key": entry["public_key"],
                            "fingerprint": entry["fingerprint"],
                            "sock": None,
                            "verified": False,
                            "first_registered": entry.get("first_registered", time.time())
                        }
                print(f"[server] Loaded {len(data)} users from persistent directory")
        except Exception as e:
            print(f"[server] Error loading directory: {e}")

def save_persistent_directory():
    """Save user directory to disk (excluding sockets)"""
    from pathlib import Path
    directory_file = Path("server_directory.json")
    try:
        # Create a serializable version without socket objects
        serializable_dir = {}
        for username, entry in directory.items():
            if entry.get("public_key") and entry.get("fingerprint"):
                serializable_dir[username] = {
                    "public_key": entry["public_key"],
                    "fingerprint": entry["fingerprint"],
                    "first_registered": entry.get("first_registered", time.time())
                }
        
        with open(directory_file, 'w', encoding='utf-8') as f:
            json.dump(serializable_dir, f, indent=2)
    except Exception as e:
        print(f"[server] Error saving directory: {e}")

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

                # If this is a returning user, verify they have the same public key
                if existing and existing.get("fingerprint"):
                    if existing["fingerprint"] != full_fp:
                        send_json(sock, {"type": "ERROR", "error": "key_mismatch", 
                                       "message": "Your key doesn't match the registered key for this username"})
                        continue
                    print(f"[server] Returning user {req_username} attempting reconnection")
                else:
                    print(f"[server] New user {req_username} attempting registration")
                
                # Generate challenge for proof of possession
                challenge = secrets.token_hex(32)  # 256-bit random challenge
                pending_challenge = {
                    "username": req_username, 
                    "public_key": pub, 
                    "fingerprint": full_fp, 
                    "challenge": challenge,
                    "is_new_user": existing is None
                }
                
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
                    
                    # Preserve first registration time for persistent users
                    existing_entry = directory.get(reg_username, {})
                    first_registered = existing_entry.get("first_registered", time.time())
                    is_new_user = pending_challenge.get("is_new_user", True)
                    
                    directory[reg_username] = {
                        "public_key": pending_challenge["public_key"],
                        "fingerprint": pending_challenge["fingerprint"],
                        "sock": sock,
                        "verified": True,
                        "first_registered": first_registered
                    }
                    sock_to_user[sock] = reg_username
                    
                    # Save to persistent storage
                    save_persistent_directory()
                    
                    pending_challenge = None

                    # Send successful registration and roster
                    roster = [{"username": u, "fingerprint": d["fingerprint"][:16] + "..."}  # Show shortened for display
                              for u, d in directory.items() if d.get("sock") and d.get("verified")]
                    
                    registration_msg = "reconnected" if not is_new_user else "registered"
                    send_json(sock, {"type": "REGISTERED", "you": reg_username, "roster": roster, 
                                   "status": registration_msg})
                    
                    print(f"[server] ✅ User {reg_username} {registration_msg} and verified")
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

            # 3) PM (ciphertext only; server validates sender, signature and replay)
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

                # Check rate limiting
                if not check_rate_limit(actual_from):
                    send_json(sock, {"type": "ERROR", "error": "rate_limited"})
                    continue

                to = msg.get("to")
                ciphertext_b64 = msg.get("ciphertext_b64")
                signature_b64 = msg.get("signature_b64")
                nonce = msg.get("nonce")
                timestamp = msg.get("timestamp")

                # Validate required fields
                if not all([to, ciphertext_b64, signature_b64, nonce, timestamp]):
                    send_json(sock, {"type": "ERROR", "error": "missing_required_fields"})
                    continue

                # Check recipient exists and is verified
                entry = directory.get(to)
                if not entry or not entry.get("sock") or not entry.get("verified"):
                    send_json(sock, {"type": "ERROR", "error": "user_not_available", "to": to})
                    continue

                # Anti-replay protection
                if is_replay_attack(actual_from, nonce, timestamp):
                    send_json(sock, {"type": "ERROR", "error": "replay_attack_detected"})
                    continue

                # Verify message signature
                sender_entry = directory.get(actual_from)
                if not sender_entry:
                    send_json(sock, {"type": "ERROR", "error": "sender_not_found"})
                    continue

                message_data = create_signed_message_data(actual_from, to, ciphertext_b64, nonce, timestamp)
                if not verify_message_signature(sender_entry["public_key"], message_data, signature_b64):
                    send_json(sock, {"type": "ERROR", "error": "invalid_message_signature"})
                    continue
                    
                # Use validated sender identity and forward verified message
                payload = {
                    "type": "PM",
                    "from": actual_from,  # Use validated identity, not claimed
                    "to": to,
                    "alg": msg.get("alg", "RSA-OAEP-SHA256"),
                    "ciphertext_b64": ciphertext_b64,
                    "signature_b64": signature_b64,
                    "nonce": nonce,
                    "timestamp": timestamp,
                    "sig_alg": "PSS-SHA256",
                    "verified": True  # Server attests message was verified
                }
                try:
                    send_json(entry["sock"], payload)
                    send_json(sock, {"type": "PM_ACK", "to": to, "nonce": nonce})
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
    # Load persistent directory at startup
    load_persistent_directory()
    
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
