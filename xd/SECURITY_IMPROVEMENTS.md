# Mejoras de Seguridad - EncryptedChat

## Problemas Identificados y Solucionados

### 1. ❌ Problema: Suplantación del campo "from" 
**Antes**: Un cliente malicioso podía enviar PMs indicando ser otro usuario.

**✅ Solución**: 
- El servidor ahora valida que el campo "from" corresponda al username realmente autenticado del socket
- Se mantiene un mapeo `sock_to_user` para validación
- Si se detecta suplantación, se envía error "from_spoofing_detected"

### 2. ❌ Problema: Registro sin prueba de posesión de clave privada
**Antes**: Cualquier atacante podía registrarse con cualquier clave pública, sin demostrar que posee la privada correspondiente.

**✅ Solución**: 
- Implementado **challenge-response** con firma digital
- El servidor genera un desafío aleatorio (256-bit)
- El cliente debe firmar el desafío con PSS padding + SHA-256
- Solo usuarios que demuestren posesión de la clave privada son marcados como "verified"

### 3. ❌ Problema: Hijacking de usuarios existentes
**Antes**: Un atacante podía re-registrarse como usuario existente y cambiar su clave pública.

**✅ Solución**: 
- El servidor verifica si un username ya está tomado por una conexión verificada
- Solo permite re-registro si no hay conexión activa verificada

### 4. ❌ Problema: Fingerprints débiles
**Antes**: Solo se usaban 8 bytes de SHA-256 (64 bits), vulnerable a ataques de colisión.

**✅ Solución**: 
- Se almacenan **fingerprints completos SHA-256** (256 bits)
- Se muestran versiones abreviadas para interfaz de usuario
- Mayor resistencia contra ataques de colisión

### 5. ❌ Problema: Sin persistencia de claves conocidas
**Antes**: No había detección de cambios de clave entre sesiones.

**✅ Solución**: 
- Implementado **TOFU (Trust On First Use)**
- Las claves se guardan en `{username}_known_keys.json`
- Si una clave cambia, se alerta al usuario y requiere confirmación
- Protege contra ataques MITM persistentes

## Nuevos Mensajes del Protocolo

### CHALLENGE (Server → Client)
```json
{
  "type": "CHALLENGE",
  "challenge": "64-char-hex-string",
  "message": "Sign this challenge with your private key to complete registration"
}
```

### CHALLENGE_RESPONSE (Client → Server)
```json
{
  "type": "CHALLENGE_RESPONSE", 
  "signature": "base64-encoded-signature"
}
```

### Nuevos Errores
- `username_taken`: Usuario ya registrado por otra conexión
- `no_pending_challenge`: Respuesta a desafío sin desafío pendiente
- `missing_signature`: Falta la firma en la respuesta
- `invalid_signature`: La firma no es válida
- `from_spoofing_detected`: Intento de suplantación detectado
- `not_registered`: Intento de enviar PM sin estar registrado

## Flujo de Registro Mejorado

1. **Cliente** → `REGISTER` con username, public_key, fingerprint
2. **Servidor** → `CHALLENGE` con desafío aleatorio
3. **Cliente** → `CHALLENGE_RESPONSE` con firma del desafío  
4. **Servidor** → `REGISTERED` si la firma es válida, `ERROR` si no

## Indicadores de Seguridad

### En el Cliente:
- `✅ Registrado exitosamente` - Verificación exitosa
- `[TOFU] Nueva clave guardada` - Primera vez viendo esta clave
- `[TOFU] Clave confirmada` - Clave coincide con versión conocida
- `⚠️ [TOFU ALERT] ¡La clave de X ha cambiado!` - Posible ataque MITM

### En el Servidor:
- Logs de intentos de suplantación
- Validación de firmas
- Control de usuarios verificados vs no verificados

## Limitaciones Restantes

1. **El servidor sigue siendo un punto de confianza**: Si está comprometido, puede realizar ataques sofisticados
2. **Sin autenticación mutua**: Los clientes no verifican la identidad del servidor
3. **Sin forward secrecy**: RSA sin intercambio de claves efímeras
4. **Metadatos expuestos**: El servidor ve quién habla con quién

## Próximas Mejoras Recomendadas

1. **Certificate Pinning**: Validar certificado del servidor
2. **Double Ratchet**: Implementar forward secrecy como Signal
3. **Onion routing**: Ocultar metadatos de comunicación
4. **Key transparency**: Log público de claves para detectar ataques

## Testing

Para probar las mejoras:

1. Ejecutar servidor: `python3 server.py`
2. Ejecutar clientes: `python3 client.py` 
3. Intentar ataques:
   - Modificar el campo "from" en PMs
   - Registrarse sin la clave privada correcta
   - Cambiar claves de usuarios existentes

El sistema ahora debe detectar y bloquear estos ataques.
