import socket
import threading

HOST = '127.0.0.1'  # Cambia esto por la IP del servidor
PORT = 5000

def receive_messages(sock):
    while True:
        try:
            msg = sock.recv(1024).decode()
            print(msg)
        except:
            print("[!] Conexión cerrada.")
            break

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    
    name = input("Tu nombre: ")
    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    while True:
        msg = input()
        if msg.lower() == 'salir':
            break
        full_msg = f"{name}: {msg}"
        client.send(full_msg.encode())
    
    client.close()

if __name__ == "__main__":
    main()
