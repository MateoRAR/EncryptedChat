import socket
import threading

HOST = '0.0.0.0'
PORT = 5000

clients = []

def broadcast(msg, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.send(msg)
            except:
                clients.remove(client)

def handle_client(client_socket):
    while True:
        try:
            msg = client_socket.recv(1024)
            if not msg:
                break
            broadcast(msg, client_socket)
        except:
            break
    clients.remove(client_socket)
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[+] Servidor escuchando en {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"[+] Nueva conexión desde {addr}")
        clients.append(client_socket)
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

if _name_ == "_main_":
    main()
