#!/usr/bin/env python3
"""
Script de prueba avanzado para las mejoras de seguridad v2
"""
import socket
import json
import base64
import time
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

def send_json(sock, obj):
    data = json.dumps(obj, ensure_ascii=False).encode() + b"\n"
    sock.sendall(data)

def recv_lines(sock):
    return sock.makefile("r", encoding="utf-8", newline="\n")

def create_signed_message_data(from_user, to_user, ciphertext_b64, nonce, timestamp):
    return f"{from_user}|{to_user}|{ciphertext_b64}|{nonce}|{timestamp:.0f}"

def sign_message(private_key, message_data):
    signature = private_key.sign(
        message_data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def test_replay_attack():
    """Test: Intentar enviar el mismo mensaje dos veces (replay attack)"""
    print("\n=== TEST 1: Replay Attack ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        # Crear clave de prueba
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        
        # Simular registro exitoso (saltando challenge para simplificar)
        print("Simulando registro...")
        
        # Crear mensaje PM con nonce y timestamp
        ciphertext_b64 = base64.b64encode(b"mensaje_de_prueba").decode()
        nonce = secrets.token_hex(16)
        timestamp = time.time()
        
        message_data = create_signed_message_data("testuser", "target", ciphertext_b64, nonce, timestamp)
        signature = sign_message(private_key, message_data)
        
        pm_message = {
            "type": "PM",
            "from": "testuser",
            "to": "target", 
            "ciphertext_b64": ciphertext_b64,
            "signature_b64": signature,
            "nonce": nonce,
            "timestamp": timestamp
        }
        
        # Enviar mensaje primera vez
        send_json(sock, pm_message)
        f = recv_lines(sock)
        response1 = json.loads(next(f))
        print(f"Primera vez: {response1}")
        
        # Enviar mismo mensaje segunda vez (replay)
        print("Intentando replay del mismo mensaje...")
        send_json(sock, pm_message)
        response2 = json.loads(next(f))
        print(f"Segunda vez: {response2}")
        
        if response2.get("error") == "replay_attack_detected":
            print("✅ Replay attack detectado y bloqueado!")
        else:
            print("❌ Replay attack no detectado - vulnerabilidad presente")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def test_timestamp_manipulation():
    """Test: Mensaje con timestamp muy antiguo"""
    print("\n=== TEST 2: Timestamp Manipulation ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        
        # Crear mensaje con timestamp antiguo (10 minutos atrás)
        ciphertext_b64 = base64.b64encode(b"mensaje_antiguo").decode()
        nonce = secrets.token_hex(16)
        old_timestamp = time.time() - 600  # 10 minutos atrás
        
        message_data = create_signed_message_data("testuser", "target", ciphertext_b64, nonce, old_timestamp)
        signature = sign_message(private_key, message_data)
        
        send_json(sock, {
            "type": "PM",
            "from": "testuser",
            "to": "target",
            "ciphertext_b64": ciphertext_b64,
            "signature_b64": signature,
            "nonce": nonce,
            "timestamp": old_timestamp
        })
        
        f = recv_lines(sock)
        response = json.loads(next(f))
        print(f"Respuesta: {response}")
        
        if response.get("error") == "replay_attack_detected":
            print("✅ Timestamp antiguo detectado y bloqueado!")
        else:
            print("❌ Timestamp antiguo no detectado - vulnerabilidad presente")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def test_invalid_signature():
    """Test: Mensaje con firma inválida"""
    print("\n=== TEST 3: Invalid Signature ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        # Crear mensaje con firma inválida
        ciphertext_b64 = base64.b64encode(b"mensaje_con_firma_falsa").decode()
        nonce = secrets.token_hex(16)
        timestamp = time.time()
        
        send_json(sock, {
            "type": "PM",
            "from": "testuser",
            "to": "target",
            "ciphertext_b64": ciphertext_b64,
            "signature_b64": base64.b64encode(b"firma_falsa").decode(),
            "nonce": nonce,
            "timestamp": timestamp
        })
        
        f = recv_lines(sock)
        response = json.loads(next(f))
        print(f"Respuesta: {response}")
        
        if response.get("error") == "invalid_message_signature":
            print("✅ Firma inválida detectada y bloqueada!")
        else:
            print("❌ Firma inválida no detectada - vulnerabilidad presente")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def test_rate_limiting():
    """Test: Enviar muchos mensajes muy rápido"""
    print("\n=== TEST 4: Rate Limiting ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        
        print("Enviando 35 mensajes muy rápido...")
        rate_limited = False
        
        for i in range(35):
            ciphertext_b64 = base64.b64encode(f"mensaje_{i}".encode()).decode()
            nonce = secrets.token_hex(16)
            timestamp = time.time()
            
            message_data = create_signed_message_data("testuser", "target", ciphertext_b64, nonce, timestamp)
            signature = sign_message(private_key, message_data)
            
            send_json(sock, {
                "type": "PM",
                "from": "testuser", 
                "to": "target",
                "ciphertext_b64": ciphertext_b64,
                "signature_b64": signature,
                "nonce": nonce,
                "timestamp": timestamp
            })
            
            # No leer respuesta para ir más rápido
            if i % 10 == 0:
                print(f"  Enviados {i+1}/35...")
        
        # Leer respuestas
        f = recv_lines(sock)
        for _ in range(5):  # Leer algunas respuestas
            try:
                response = json.loads(next(f))
                if response.get("error") == "rate_limited":
                    rate_limited = True
                    break
            except:
                break
        
        if rate_limited:
            print("✅ Rate limiting activado correctamente!")
        else:
            print("❌ Rate limiting no funcionó - vulnerabilidad presente")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def test_missing_fields():
    """Test: PM sin campos obligatorios"""
    print("\n=== TEST 5: Missing Required Fields ===")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        sock.connect((SERVER_HOST, SERVER_PORT))
        
        # Enviar PM sin nonce
        send_json(sock, {
            "type": "PM",
            "from": "testuser",
            "to": "target",
            "ciphertext_b64": base64.b64encode(b"test").decode(),
            "signature_b64": "fake_sig",
            "timestamp": time.time()
            # Missing nonce
        })
        
        f = recv_lines(sock)
        response = json.loads(next(f))
        print(f"Sin nonce: {response}")
        
        if response.get("error") == "missing_required_fields":
            print("✅ Campos faltantes detectados!")
        else:
            print("❌ No se detectaron campos faltantes")
            
    except Exception as e:
        print(f"Error en test: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def main():
    print("🔒 Script de Prueba Avanzado - EncryptedChat v2")
    print("=" * 60)
    print("Probando nuevas defensas: firmas, anti-replay, rate limiting...")
    print("Asegúrate de que el servidor v2 esté ejecutándose en localhost:5000")
    
    input("Presiona Enter para comenzar los tests...")
    
    test_invalid_signature()
    test_missing_fields()
    test_timestamp_manipulation() 
    test_replay_attack()
    test_rate_limiting()
    
    print("\n" + "=" * 60)
    print("🎯 Tests avanzados completados!")
    print("Si ves ✅ en todos los tests, las defensas v2 están funcionando.")
    print("Cualquier ❌ indica una vulnerabilidad que necesita atención.")
    print("\n🛡️  Sistema preparado para enfrentar ataques sofisticados!")

if __name__ == "__main__":
    main()
