#!/usr/bin/env python3
import socket
import threading
import json

HOST = "0.0.0.0"
PORT = 5000

# username -> { "public_key": str, "fingerprint": str, "sock": socket.socket }
directory = {}
clients = set()

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

            # 1) REGISTER
            if mtype == "REGISTER":
                username = msg.get("username")
                pub = msg.get("public_key")
                fp = msg.get("fingerprint")
                if not username or not pub or not fp:
                    send_json(sock, {"type": "ERROR", "error": "invalid_register"})
                    continue

                # store / update
                directory[username] = {"public_key": pub, "fingerprint": fp, "sock": sock}

                # ACK and (optionally) send roster
                roster = [{"username": u, "fingerprint": d["fingerprint"]}
                          for u, d in directory.items() if d.get("sock")]
                send_json(sock, {"type": "REGISTERED", "you": username, "roster": roster})

            # 2) GET_PUBLIC_KEY
            elif mtype == "GET_PUBLIC_KEY":
                target = msg.get("username")
                entry = directory.get(target)
                if not entry:
                    send_json(sock, {"type": "PUBLIC_KEY", "username": target, "found": False})
                else:
                    send_json(sock, {
                        "type": "PUBLIC_KEY",
                        "username": target,
                        "found": True,
                        "public_key": entry["public_key"],
                        "fingerprint": entry["fingerprint"],
                    })

            # 3) PM (ciphertext only; server blindly relays)
            elif mtype == "PM":
                to = msg.get("to")
                entry = directory.get(to)
                if not entry or not entry.get("sock"):
                    send_json(sock, {"type": "ERROR", "error": "user_not_available", "to": to})
                    continue
                # add relay metadata minimally
                payload = {
                    "type": "PM",
                    "from": msg.get("from"),
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
        # keep directory entry but clear socket if present
        if username and directory.get(username, {}).get("sock") is sock:
            directory[username]["sock"] = None
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
