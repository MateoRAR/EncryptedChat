#!/usr/bin/env python3
"""
Script de prueba de seguridad para demostrar las mejoras implementadas
"""
import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

def send_json(sock, obj):
    data = json.dumps(obj, ensure_ascii=False).encode() + b"\n"
    sock.sendall(data)

def recv_lines(sock):
    return sock.makefile("r", encoding="utf-8", newline="\n")

def test_from_spoofing():
    """Test 1: Intentar suplantar el campo 'from' en un PM"""
    print("\n=== TEST 1: From Spoofing Attack ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        # Generar clave falsa para este test
        fake_key = rsa.generate_private_key(65537, 2048, default_backend())
        fake_pub_pem = fake_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        
        # Intentar registrarse como "attacker"
        send_json(sock, {
            "type": "REGISTER",
            "username": "attacker",
            "public_key": fake_pub_pem,
            "fingerprint": "fake_fp"
        })
        
        # Leer respuesta
        f = recv_lines(sock)
        response = json.loads(next(f))
        print(f"Registro: {response}")
        
        if response.get("type") == "CHALLENGE":
            print("Sin challenge-response, este ataque fallaría")
            return
            
        # Intentar enviar PM como si fuera "alice"
        send_json(sock, {
            "type": "PM",
            "from": "alice",  # ¡Suplantación!
            "to": "bob",
            "ciphertext_b64": "fake_message"
        })
        
        response = json.loads(next(f))
        print(f"Respuesta al PM suplantado: {response}")
        
        if response.get("error") == "from_spoofing_detected":
            print(" Ataque detectado y bloqueado exitosamente!")
        else:
            print(" Ataque no detectado - vulnerabilidad presente")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def test_registration_without_private_key():
    """Test 2: Intentar registrarse sin tener la clave privada"""
    print("\n=== TEST 2: Registration Without Private Key ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        # Generar clave pública aleatoria (fingiendo que es de Alice)
        fake_key = rsa.generate_private_key(65537, 2048, default_backend())
        fake_pub_pem = fake_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        
        # Intentar registrarse como "alice" con clave falsa
        send_json(sock, {
            "type": "REGISTER", 
            "username": "alice",
            "public_key": fake_pub_pem,
            "fingerprint": "fake_fingerprint"
        })
        
        f = recv_lines(sock)
        response = json.loads(next(f))
        print(f"Respuesta de registro: {response}")
        
        if response.get("type") == "CHALLENGE":
            print(" Challenge solicitado - intentando respuesta falsa...")
            
            # Intentar responder con firma inválida
            send_json(sock, {
                "type": "CHALLENGE_RESPONSE",
                "signature": base64.b64encode(b"fake_signature").decode()
            })
            
            response = json.loads(next(f))
            print(f"Respuesta al challenge: {response}")
            
            if response.get("error") == "invalid_signature":
                print(" Firma inválida detectada - ataque bloqueado!")
            else:
                print(" Firma inválida aceptada - vulnerabilidad presente")
        else:
            print(" No se solicitó challenge - vulnerabilidad presente")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def test_username_hijacking():
    """Test 3: Intentar secuestrar un username existente"""
    print("\n=== TEST 3: Username Hijacking Attack ===")
    
    try:
        # Simular que "alice" ya está registrada
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.connect((SERVER_HOST, SERVER_PORT))
        
        # Intentar registrarse como "alice" desde otra conexión
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock2.connect((SERVER_HOST, SERVER_PORT))
        
        fake_key = rsa.generate_private_key(65537, 2048, default_backend())
        fake_pub_pem = fake_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        
        send_json(sock2, {
            "type": "REGISTER",
            "username": "alice",  # Username ya en uso
            "public_key": fake_pub_pem,
            "fingerprint": "hijack_attempt"
        })
        
        f = recv_lines(sock2)
        response = json.loads(next(f))
        print(f"Respuesta de hijacking: {response}")
        
        if response.get("error") == "username_taken":
            print("Intento de hijacking detectado y bloqueado!")
        else:
            print("Hijacking no detectado - vulnerabilidad presente")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock1.close()
            sock2.close()
        except:
            pass

def main():
    print("🔒 Script de Prueba de Seguridad - EncryptedChat")
    print("=" * 50)
    print("Este script demuestra los ataques mitigados por las mejoras de seguridad.")
    print("Asegúrate de que el servidor esté ejecutándose en localhost:5000")
    
    input("Presiona Enter para comenzar los tests...")
    
    test_from_spoofing()
    test_registration_without_private_key() 
    test_username_hijacking()
    
    print("\n" + "=" * 50)
    print("Tests completados!")
    print("Si ves '✅' en todos los tests, las mejoras están funcionando correctamente.")
    print("Si ves '❌', hay vulnerabilidades que necesitan atención.")

if __name__ == "__main__":
    main()
