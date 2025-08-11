# EncryptedChat v2.0 - Sistema de Chat Seguro con Cifrado End-to-End

## Descripción General

EncryptedChat v2.0 es un sistema de mensajería instantánea diseñado para proporcionar comunicaciones seguras mediante cifrado RSA end-to-end con múltiples capas de protección contra ataques man-in-the-middle (MITM), replay attacks, y otras amenazas comunes en comunicaciones distribuidas.

## Evolución de Seguridad

### Mitigaciones Básicas v1.0

La primera versión del sistema implementó las siguientes defensas fundamentales:

#### 1. Validación de Identidad del Remitente (Anti-Spoofing)
- **Mapeo sock-to-user**: El servidor mantiene una relación entre conexiones y usuarios autenticados
- **Validación del campo "from"**: Verificación obligatoria de que el campo "from" coincida con el usuario real de la conexión
- **Error específico**: Respuesta "from_spoofing_detected" cuando se detecta suplantación de identidad

#### 2. Autenticación Challenge-Response
- **Prueba de posesión de clave privada**: Sistema de desafío criptográfico durante el registro
- **Desafío aleatorio**: Generación de tokens de 256 bits para cada intento de registro
- **Verificación PSS+SHA256**: Los usuarios deben firmar el desafío para completar el registro
- **Prevención de registro falso**: Imposible registrarse sin demostrar posesión de la clave privada

#### 3. Fingerprints SHA-256 Completos
- **Hashes completos**: Migración de fingerprints de 64 bits a SHA-256 completo (256 bits)
- **Resistencia a colisiones**: Mayor seguridad contra ataques de colisión de hash
- **Verificación mejorada**: Identificación más robusta de claves públicas

#### 4. Sistema TOFU (Trust-On-First-Use)
- **Persistencia de claves conocidas**: Almacenamiento local de claves públicas de otros usuarios
- **Detección de cambios**: Alertas automáticas cuando una clave pública cambia
- **Confirmación de usuario**: Proceso manual para aceptar cambios de clave
- **Protección contra MITM persistente**: Defensa contra ataques de sustitución de clave a largo plazo

#### 5. Control de Usuarios Verificados
- **Estado de verificación**: Distinción entre usuarios registrados y verificados
- **Directorio controlado**: Solo usuarios que pasan el challenge-response son marcados como verificados
- **Acceso restringido**: Las funcionalidades críticas requieren verificación completa

### Mejoras Avanzadas v2.0

La segunda versión expandió significativamente las capacidades de seguridad:

## Características Principales

### Arquitectura de Seguridad Multicapa

El sistema implementa una arquitectura de defensa en profundidad con seis capas de protección:

1. **Canal de Comunicación** - Base para futuras implementaciones TLS
2. **Autenticación** - Sistema challenge-response con persistencia
3. **Autorización** - Validación de identidad y límites de uso  
4. **Integridad** - Verificación criptográfica obligatoria
5. **Anti-Replay** - Protección contra retransmisión de mensajes
6. **Disponibilidad** - Protección contra ataques de denegación de servicio

### Funcionalidades de Seguridad

#### 1. Verificación Obligatoria de Firmas e Integridad

- **Firmas PSS+SHA256 obligatorias**: Todos los mensajes privados deben estar firmados digitalmente
- **Verificación doble**: El servidor verifica las firmas antes del reenvío, y el cliente receptor las verifica independientemente
- **Datos firmados estructurados**: Se firma la cadena "from|to|ciphertext|nonce|timestamp" para garantizar integridad total
- **Indicadores de seguridad**: El cliente muestra el estado de verificación de cada mensaje recibido

#### 2. Protección Anti-Replay Robusta

- **Nonces únicos**: Cada mensaje incluye un identificador único de 128 bits generado criptográficamente
- **Ventana temporal**: Los mensajes solo son válidos dentro de una ventana de 5 minutos desde su creación
- **Tracking histórico**: El servidor mantiene un registro de los últimos 1000 nonces por usuario
- **Tolerancia a desfase**: Se acepta hasta 30 segundos de diferencia entre relojes de cliente y servidor

#### 3. Rate Limiting y Protección DoS

- **Límites de velocidad**: Máximo 30 mensajes por minuto por usuario
- **Ventana deslizante**: El conteo se actualiza continuamente usando una ventana móvil de 60 segundos
- **Respuesta específica**: Error dedicado "rate_limited" cuando se exceden los límites

#### 4. Persistencia Segura y Control de Acceso

- **Directorio persistente**: Los usuarios registrados se almacenan en server_directory.json
- **Verificación de consistencia**: Al reconectarse, se verifica que la clave pública coincida con la registrada
- **Prevención de squatting**: Imposible registrarse con un nombre de usuario ya tomado tras reinicio del servidor
- **Auditoría temporal**: Timestamp de primer registro para análisis forense

#### 5. Sistema Trust-On-First-Use (TOFU)

- **Persistencia de claves conocidas**: Los clientes almacenan las claves públicas de otros usuarios
- **Detección de cambios**: Alerta automática si la clave pública de un usuario cambia
- **Confirmación manual**: El usuario debe aprobar explícitamente cambios de clave
- **Fingerprints completos**: Se utilizan hashes SHA-256 completos en lugar de versiones truncadas

#### 6. Autenticación Challenge-Response

- **Prueba de posesión**: Los usuarios deben demostrar que poseen la clave privada correspondiente
- **Desafío criptográfico**: El servidor genera un desafío aleatorio de 256 bits
- **Verificación de firma**: El cliente debe firmar el desafío con PSS+SHA256
- **Prevención de suplantación**: Imposible registrarse sin la clave privada correcta

## Arquitectura del Sistema

### Componentes Principales

#### Servidor (server.py)
- Maneja conexiones concurrentes mediante threading
- Implementa el directorio de usuarios con persistencia
- Verifica todas las firmas digitales antes del reenvío
- Gestiona protecciones anti-replay y rate limiting
- Proporciona confirmaciones de entrega

#### Cliente (client.py)
- Genera y gestiona claves RSA-2048 por usuario
- Implementa cifrado RSA-OAEP para mensajes
- Firma todos los mensajes con PSS+SHA256
- Mantiene sistema TOFU para claves conocidas
- Proporciona indicadores visuales de seguridad

### Flujo de Comunicación Segura

1. **Generación de Mensaje**
   - El cliente genera un nonce único y timestamp actual
   - Cifra el contenido con la clave pública del destinatario
   - Crea una cadena de datos estructurada para firma
   - Firma digitalmente usando su clave privada

2. **Validación del Servidor**
   - Verifica que el usuario no exceda límites de velocidad
   - Comprueba que el nonce no haya sido usado y el timestamp sea válido
   - Valida la firma digital del remitente
   - Confirma que el destinatario existe y está conectado

3. **Entrega y Verificación**
   - Reenvía el mensaje marcado como verificado por el servidor
   - Envía confirmación de entrega al remitente
   - El destinatario verifica independientemente la firma
   - Se muestran indicadores de estado de seguridad

## Protocolos de Mensaje

### Registro de Usuario
```
Cliente → Servidor: REGISTER {username, public_key, fingerprint}
Servidor → Cliente: CHALLENGE {challenge, message}
Cliente → Servidor: CHALLENGE_RESPONSE {signature}
Servidor → Cliente: REGISTERED {you, roster, status}
```

### Mensaje Privado
```
Cliente → Servidor: PM {from, to, ciphertext_b64, signature_b64, nonce, timestamp, sig_alg}
Servidor → Cliente: PM {from, to, ciphertext_b64, signature_b64, nonce, timestamp, sig_alg, verified}
Servidor → Remitente: PM_ACK {to, nonce}
```

### Obtención de Clave Pública
```
Cliente → Servidor: GET_PUBLIC_KEY {username}
Servidor → Cliente: PUBLIC_KEY {username, found, public_key, fingerprint}
```

## Resistencia a Ataques

### Comparativa de Mitigaciones por Versión

| Ataque | v1.0 | v2.0 | Descripción de la Mejora |
|--------|------|------|--------------------------|
| **From Spoofing** | Mitigado | Mitigado | Validación de identidad del remitente implementada en v1.0 |
| **Registration Hijacking** | Mitigado | Mitigado | Challenge-response con prueba de posesión desde v1.0 |
| **Replay Attacks** | Vulnerable | Mitigado | Nonces únicos y ventanas temporales agregados en v2.0 |
| **Message Tampering** | Vulnerable | Mitigado | Firmas obligatorias y verificación doble en v2.0 |
| **DoS via Spam** | Vulnerable | Mitigado | Rate limiting por usuario implementado en v2.0 |
| **Username Squatting** | Vulnerable | Mitigado | Persistencia de directorio agregada en v2.0 |
| **Signature Stripping** | Vulnerable | Mitigado | Campos de firma obligatorios en protocolo v2.0 |
| **Timestamp Manipulation** | Vulnerable | Mitigado | Ventanas de validez y tolerancia en v2.0 |
| **Key Substitution** | Parcialmente | Mitigado | TOFU básico en v1.0, mejorado con persistencia en v2.0 |

### Ataques Mitigados por Versión

#### Defendidos desde v1.0
- **From Spoofing**: Validación obligatoria de identidad del remitente
- **Registration Hijacking**: Sistema challenge-response con prueba de posesión
- **Key Substitution (básico)**: Sistema TOFU con confirmación manual
- **Weak Fingerprints**: SHA-256 completo en lugar de versiones truncadas

#### Nuevas Defensas en v2.0
- **Replay Attacks**: Nonces únicos y ventanas temporales
- **Message Tampering**: Firmas digitales obligatorias con verificación doble
- **DoS via Spam**: Rate limiting por usuario con ventanas deslizantes
- **Username Squatting**: Persistencia de directorio con verificación de claves
- **Signature Stripping**: Campos de firma obligatorios en el protocolo
- **Timestamp Manipulation**: Ventanas de validez y tolerancia controlada

### Indicadores de Seguridad en Cliente

El cliente proporciona indicadores visuales del estado de seguridad de cada mensaje:

- **Verificado completamente**: Mensaje verificado tanto por servidor como cliente
- **Verificado por servidor**: Solo verificación del servidor completada
- **Sin verificación**: Mensaje sin capacidades de verificación (compatibilidad)
- **Clave faltante**: No se puede verificar por falta de clave pública del remitente
- **Firma inválida**: Posible ataque detectado, mensaje comprometido

## Instalación y Uso

### Requisitos
- Python 3.7+
- Biblioteca cryptography (`pip install cryptography`)

### Ejecución

#### Servidor
```bash
python3 server.py
```
El servidor se ejecuta en puerto 5000 por defecto y crea automáticamente el archivo de persistencia.

#### Cliente
```bash
python3 client.py
```
Solicita un nombre de usuario y genera automáticamente claves RSA si no existen.

### Comandos del Cliente

- `/pm <usuario> <mensaje>` - Enviar mensaje privado cifrado y firmado
- `/say <mensaje>` - Enviar mensaje público a la sala (texto claro)
- `/quit` - Salir del chat

### Archivos Generados

- `.keys/{username}_private.pem` - Clave privada del usuario
- `.keys/{username}_public.pem` - Clave pública del usuario  
- `.keys/{username}_known_keys.json` - Claves conocidas del usuario (TOFU)
- `server_directory.json` - Directorio persistente del servidor

## Testing y Validación

### Scripts de Prueba

#### Pruebas Básicas (security_test.py)
- Validación de suplantación de identidad
- Verificación de registro sin clave privada
- Detección de hijacking de nombres de usuario

#### Pruebas Avanzadas (security_test_v2.py)
- Detección de replay attacks
- Validación de manipulación de timestamps
- Verificación de firmas inválidas
- Pruebas de rate limiting
- Validación de campos obligatorios

### Ejecución de Pruebas
```bash
# Pruebas básicas
python3 security_test.py

# Pruebas avanzadas
python3 security_test_v2.py

# Ver resumen completo
python3 summary_v2.py
```

## Limitaciones Conocidas

### Vulnerabilidades Restantes

1. **Canal no Autenticado**: La comunicación entre cliente y servidor no utiliza TLS, permitiendo ataques de interceptación pasiva

2. **Sin Forward Secrecy**: El compromiso de una clave privada afecta a todos los mensajes históricos cifrados con esa clave

3. **Exposición de Metadatos**: El servidor puede observar patrones de comunicación (quién habla con quién y cuándo)

4. **Punto Único de Confianza**: El servidor centralizado representa un punto único de falla si es comprometido

### Mejoras Futuras Recomendadas

- Implementación de TLS 1.3 con certificate pinning
- Adopción del protocolo Signal o Double Ratchet para forward secrecy
- Arquitectura descentralizada o federada
- Implementación de onion routing para proteger metadatos
- Padding y ofuscación temporal para análisis de tráfico

## Documentación Técnica

Para detalles técnicos específicos sobre la implementación, consultar:

- `SECURITY_IMPROVEMENTS.md` - Mejoras básicas de seguridad
- `ADVANCED_SECURITY.md` - Características avanzadas de seguridad v2.0
- Código fuente comentado en `server.py` y `client.py`

## Casos de Uso

Este sistema está diseñado para:

- Demostraciones académicas de seguridad en comunicaciones
- Entornos de prueba donde se requiere resistencia a ataques MITM
- Comunicaciones en redes locales con requisitos de integridad
- Validación de conceptos de criptografía aplicada

El sistema proporciona un balance entre seguridad robusta y simplicidad de implementación, siendo adecuado para entornos educativos y de investigación en ciberseguridad.
