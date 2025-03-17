# Documentación: Asterisk Audio Uploader

## Descripción General

El "Asterisk Audio Uploader" es una aplicación web que permite a los administradores de sistemas Asterisk subir archivos de audio desde su máquina local al servidor Asterisk, convirtiendo automáticamente los archivos al formato GSM que Asterisk necesita para reproducir mensajes.

## Problema que Resuelve

En sistemas Asterisk, los archivos de audio utilizados para mensajes telefónicos deben estar en formato GSM y ubicados en directorios específicos del servidor. El proceso tradicional requiere:
1. Convertir manualmente los archivos a formato GSM
2. Transferirlos al servidor mediante SCP/SFTP
3. Cambiar los permisos y propietarios adecuadamente

Esta aplicación automatiza todo el proceso en una interfaz web intuitiva.

## Arquitectura

La aplicación consta de dos componentes principales:

1. **Frontend Web**: Una interfaz web desarrollada con Flask que permite:
   - Seleccionar archivos de audio en formatos comunes (.wav, .mp3, etc.)
   - Convertirlos automáticamente a formato GSM
   - Subirlos al servidor Asterisk con los permisos correctos

2. **Script de Llamadas Automáticas**: Un script Python (`overdue_client_call.py`, (visita mi otro repo asterisk)) que utiliza estos archivos de audio para realizar llamadas automatizadas.

## Configuración y Requisitos

### Requisitos del Sistema

- **En la Máquina Local**:
  - Python 3.7+
  - FFmpeg instalado (para conversión de audio)
  - Dependencias Python: flask, paramiko, pydub, flask-wtf

- **En el Servidor Asterisk**:
  - Usuario con acceso SSH
  - Permisos para escribir en el directorio de sonidos de Asterisk

### Problemas Comunes

#### Problema de Permisos

El error más común es "Permission denied" al intentar escribir en el directorio de sonidos de Asterisk.

**Causas**:
- El directorio `/usr/share/asterisk/sounds/es_MX` es un enlace simbólico a `/etc/alternatives/asterisk-prompt-es-mx`.
- Los archivos tienen permisos 644 (rw-r--r--), que solo permiten escritura al propietario.

**Soluciones**:

1. **Solución Preferida: Ajustar Permisos del Directorio**
   ```bash
   # Ver dónde apunta realmente el enlace simbólico
   sudo ls -la /etc/alternatives/asterisk-prompt-es-mx

   # Cambiar los permisos del directorio real para que el grupo pueda escribir
   sudo chmod 775 /etc/alternatives/asterisk-prompt-es-mx

   # Asegurarse de que el grupo del directorio es asterisk
   sudo chgrp asterisk /etc/alternatives/asterisk-prompt-es-mx
   ```

2. **Solución Alternativa: Configurar Sudo sin Contraseña**
   ```bash
   # Editar el archivo sudoers
   sudo visudo

   # Agregar esta línea
   omar ALL=(ALL) NOPASSWD: /bin/mv, /bin/chown, /bin/mkdir
   ```

## Funcionamiento de la Aplicación

1. **Inicio**: El usuario accede a la aplicación web (http://192.168.13.254:5000)
2. **Configuración**: Configura la conexión SSH al servidor Asterisk
3. **Selección de Archivo**: Selecciona un archivo de audio y proporciona un nombre
4. **Conversión**: La aplicación usa FFmpeg para convertir el archivo a GSM
5. **Transferencia**: Se transfiere al servidor y se configuran los permisos adecuados
6. **Verificación**: Se muestran los archivos locales y remotos para verificación

## Integración con Sistema de Llamadas

El archivo GSM subido puede ser utilizado en el script `overdue_client_call.py` para realizar llamadas automatizadas. El script se conecta a Asterisk utilizando ARI (Asterisk REST Interface) y reproduce los mensajes.

Para usar un archivo específico, se debe configurar:

```python
"media": "sound:nombre_archivo"  # sin la extensión .gsm
```

## Configuración del Dialplan

Para que el sistema funcione correctamente, se requiere una configuración específica en el dialplan de Asterisk:

```
[from-voip]
exten => _X.,1,NoOp(Llamada saliente a ${EXTEN})
    same => n,Set(CHANNEL(audioreadformat)=ulaw)
    same => n,Set(CHANNEL(audiowriteformat)=ulaw)
    same => n,Dial(SIP/voip_issabel/${EXTEN})
    same => n,Stasis(overdue-app)
    same => n,Hangup()

[stasis-openai]
exten => _X.,1,NoOp(Llamada en Stasis: ${EXTEN})
    same => n,Answer()
    same => n,Wait(1)
    same => n,Return()
```

## Mantenimiento y Solución de Problemas

### Logs

La aplicación genera logs detallados en `audio_uploader.log` que pueden ayudar a diagnosticar problemas.

### Comandos de Diagnóstico

```bash
# Verificar instalación de FFmpeg
ffmpeg -version

# Probar conexión SSH
ssh -i ~/.ssh/synrad omar@45.61.59.204

# Verificar permisos del directorio de sonidos
ssh -i ~/.ssh/synrad omar@45.61.59.204 "ls -la /usr/share/asterisk/sounds/es_MX"

# Probar sudo sin contraseña
ssh -i ~/.ssh/synrad omar@45.61.59.204 "sudo -n chmod 644 /tmp/test.txt"
```

## Comandos de Mantenimiento

```bash
# Recargar dialplan de Asterisk
sudo asterisk -rx "dialplan reload"

# Reiniciar Asterisk
sudo systemctl restart asterisk

# Convertir archivo de audio a GSM manualmente
ffmpeg -i input.wav -ar 8000 -ac 1 -acodec gsm output.gsm

# Verificar estado de Asterisk
sudo systemctl status asterisk
```

## Créditos y Contacto

Desarrollado para sistemas Asterisk, esta herramienta facilita la gestión de archivos de audio y la configuración de llamadas automáticas.

Para dudas o soporte, contacte al administrador del sistema.