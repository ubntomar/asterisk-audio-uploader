#!/usr/bin/env python3
"""
Asterisk Audio Uploader
-----------------------
Una aplicación web que permite subir archivos de audio al servidor Asterisk,
convirtiendo automáticamente los archivos a formato GSM y colocándolos
en la ruta correcta. Soporta autenticación SSH por clave privada.

Requisitos:
- pip install flask paramiko pydub flask-wtf
- ffmpeg debe estar instalado en el sistema local
"""

import os
import tempfile
import subprocess
import logging
import traceback
from pathlib import Path
from datetime import datetime

import paramiko
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Optional
from werkzeug.utils import secure_filename

# Configuración de logging mejorada
logging.basicConfig(
    level=logging.DEBUG,  # Cambiado a DEBUG para más detalles
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("audio_uploader.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("audio_uploader")

# Configuración de la aplicación
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

# Configuración predeterminada
DEFAULT_CONFIG = {
    'ssh_host': '45.61.59.204',
    'ssh_port': 22,
    'ssh_username': 'omar',
    'auth_method': 'key',
    'ssh_password': '',
    'ssh_key_path': os.path.expanduser('~/.ssh/synrad'),
    'remote_audio_dir': '/usr/share/asterisk/sounds/es_MX',
    'local_audio_dir': os.path.expanduser('~/audios'),
}

# Asegurar que el directorio local exista
os.makedirs(DEFAULT_CONFIG['local_audio_dir'], exist_ok=True)

# Formulario para subir archivos
class AudioUploadForm(FlaskForm):
    audio_file = FileField('Archivo de Audio', 
                          validators=[
                              FileRequired(),
                              FileAllowed(['wav', 'mp3', 'ogg', 'm4a'], 'Solo archivos de audio permitidos')
                          ])
    new_filename = StringField('Nombre del archivo (sin extensión)', validators=[DataRequired()])
    submit = SubmitField('Subir')

# Formulario para configuración SSH
class SSHConfigForm(FlaskForm):
    ssh_host = StringField('Host SSH', validators=[DataRequired()], default=DEFAULT_CONFIG['ssh_host'])
    ssh_port = StringField('Puerto SSH', validators=[DataRequired()], default=str(DEFAULT_CONFIG['ssh_port']))
    ssh_username = StringField('Usuario SSH', validators=[DataRequired()], default=DEFAULT_CONFIG['ssh_username'])
    
    auth_method = SelectField('Método de Autenticación', 
                             choices=[('key', 'Clave SSH'), ('password', 'Contraseña')],
                             default=DEFAULT_CONFIG['auth_method'])
    
    ssh_password = PasswordField('Contraseña SSH', validators=[Optional()])
    ssh_key_path = StringField('Ruta a la clave SSH privada', 
                              default=DEFAULT_CONFIG['ssh_key_path'])
    
    remote_dir = StringField('Directorio Remoto', validators=[DataRequired()], 
                            default=DEFAULT_CONFIG['remote_audio_dir'])
    
    submit = SubmitField('Guardar Configuración')

def convert_to_gsm(input_file, output_file):
    """Convierte un archivo de audio a formato GSM usando ffmpeg"""
    try:
        # Asegúrate de que el directorio de salida exista
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Comando para convertir a GSM con optimización de calidad
        cmd = [
            'ffmpeg', '-y', '-i', input_file,
            '-ar', '8000', '-ac', '1',
            '-af', 'highpass=f=300, lowpass=f=3400, volume=1.5',
            '-acodec', 'gsm', output_file
        ]
        
        logger.debug(f"Ejecutando comando ffmpeg: {' '.join(cmd)}")
        
        # Ejecutar el comando
        process = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Comprobar si hubo errores
        if process.returncode != 0:
            logger.error(f"Error converting file: {process.stderr}")
            return False, process.stderr
        
        logger.info(f"Successfully converted {input_file} to GSM format")
        # Verificar que el archivo existe y tiene tamaño
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            logger.debug(f"Archivo GSM creado correctamente: {output_file}, tamaño: {os.path.getsize(output_file)} bytes")
            return True, None
        else:
            logger.error(f"Archivo GSM no existe o tiene tamaño cero: {output_file}")
            return False, "El archivo GSM no se generó correctamente"
    
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Exception during conversion: {str(e)}\n{error_details}")
        return False, str(e)

def upload_file_to_server(local_file, remote_file, ssh_config):
    """Sube un archivo al servidor remoto mediante SSH/SCP"""
    ssh_client = None
    sftp_client = None
    
    try:
        # Verificar que el archivo local existe
        if not os.path.exists(local_file):
            error_msg = f"El archivo local no existe: {local_file}"
            logger.error(error_msg)
            return False, error_msg
            
        # Verificar tamaño del archivo
        file_size = os.path.getsize(local_file)
        if file_size == 0:
            error_msg = f"El archivo local tiene tamaño cero: {local_file}"
            logger.error(error_msg)
            return False, error_msg
            
        logger.debug(f"Preparando para subir archivo: {local_file} ({file_size} bytes) a {remote_file}")
        logger.debug(f"Configuración SSH: host={ssh_config['ssh_host']}, puerto={ssh_config['ssh_port']}, "
                    f"usuario={ssh_config['ssh_username']}, método={ssh_config['auth_method']}")
        
        # Verificar ruta de clave SSH si se usa autenticación por clave
        if ssh_config['auth_method'] == 'key':
            key_path = os.path.expanduser(ssh_config['ssh_key_path'])
            if not os.path.exists(key_path):
                error_msg = f"La clave SSH no existe: {key_path}"
                logger.error(error_msg)
                return False, error_msg
            logger.debug(f"Clave SSH encontrada: {key_path}, permisos: {oct(os.stat(key_path).st_mode)[-3:]}")
        
        # Configurar cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor usando la autenticación apropiada
        if ssh_config['auth_method'] == 'key':
            # Autenticación por clave privada
            try:
                logger.debug(f"Intentando conexión SSH con clave: {ssh_config['ssh_key_path']}")
                ssh_client.connect(
                    hostname=ssh_config['ssh_host'],
                    port=int(ssh_config['ssh_port']),
                    username=ssh_config['ssh_username'],
                    key_filename=os.path.expanduser(ssh_config['ssh_key_path']),
                    timeout=10
                )
                logger.info(f"Connected to {ssh_config['ssh_host']} using SSH key")
            except Exception as e:
                error_details = traceback.format_exc()
                error_msg = f"Error connecting with SSH key: {str(e)}"
                logger.error(f"{error_msg}\n{error_details}")
                return False, error_msg
        else:
            # Autenticación por contraseña
            try:
                logger.debug(f"Intentando conexión SSH con contraseña")
                ssh_client.connect(
                    hostname=ssh_config['ssh_host'],
                    port=int(ssh_config['ssh_port']),
                    username=ssh_config['ssh_username'],
                    password=ssh_config['ssh_password'],
                    timeout=10
                )
                logger.info(f"Connected to {ssh_config['ssh_host']} using password")
            except Exception as e:
                error_details = traceback.format_exc()
                error_msg = f"Error connecting with password: {str(e)}"
                logger.error(f"{error_msg}\n{error_details}")
                return False, error_msg
        
        # Verificar existencia del directorio remoto
        try:
            logger.debug(f"Verificando existencia del directorio remoto: {os.path.dirname(remote_file)}")
            stdin, stdout, stderr = ssh_client.exec_command(f'ls -la {os.path.dirname(remote_file)}')
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                error_msg = f"El directorio remoto no existe o no se puede acceder: {os.path.dirname(remote_file)}"
                logger.error(error_msg)
                logger.error(f"Error: {stderr.read().decode('utf-8')}")
                return False, error_msg
        except Exception as e:
            error_details = traceback.format_exc()
            error_msg = f"Error verificando directorio remoto: {str(e)}"
            logger.error(f"{error_msg}\n{error_details}")
            return False, error_msg
        
        # Transferir archivo
        try:
            logger.debug(f"Iniciando transferencia SFTP: {local_file} -> {remote_file}")
            sftp_client = ssh_client.open_sftp()
            sftp_client.put(local_file, remote_file)
            logger.debug(f"Archivo transferido correctamente")
        except Exception as e:
            error_details = traceback.format_exc()
            error_msg = f"Error durante la transferencia SFTP: {str(e)}"
            logger.error(f"{error_msg}\n{error_details}")
            return False, error_msg
        
        # Establecer permisos apropiados
        try:
            logger.debug(f"Estableciendo permisos 644 en archivo remoto")
            sftp_client.chmod(remote_file, 0o644)
        except Exception as e:
            logger.warning(f"No se pudieron establecer permisos: {str(e)}")
            # No fallamos la operación por esto, continuamos
        
        # Ejecutar comando para cambiar el propietario a asterisk:asterisk
        try:
            logger.debug(f"Cambiando propietario a asterisk:asterisk")
            stdin, stdout, stderr = ssh_client.exec_command(f'sudo chown asterisk:asterisk "{remote_file}"')
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error_output = stderr.read().decode('utf-8')
                logger.warning(f"Error setting ownership: {error_output}")
                if "sudo: no tty present and no askpass program specified" in error_output:
                    error_msg = "Error: Se requiere contraseña para sudo. Configure sudo sin contraseña en el servidor."
                    logger.error(error_msg)
                    return False, error_msg
        except Exception as e:
            error_details = traceback.format_exc()
            logger.warning(f"Error executing sudo command: {str(e)}\n{error_details}")
            # No fallamos la operación por esto, el archivo ya se transfirió
        
        # Verificación final: comprobar que el archivo existe en el servidor
        try:
            stdin, stdout, stderr = ssh_client.exec_command(f'ls -la "{remote_file}"')
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                error_msg = f"No se pudo verificar el archivo en el servidor: {stderr.read().decode('utf-8')}"
                logger.error(error_msg)
                return False, error_msg
            else:
                file_info = stdout.read().decode('utf-8')
                logger.debug(f"Archivo verificado en servidor: {file_info}")
        except Exception as e:
            error_details = traceback.format_exc()
            logger.warning(f"Error verificando archivo en servidor: {str(e)}\n{error_details}")
            # No fallamos la operación por esto
        
        logger.info(f"Successfully uploaded {local_file} to {remote_file}")
        return True, None
    
    except Exception as e:
        error_details = traceback.format_exc()
        error_msg = f"Error uploading file: {str(e)}"
        logger.error(f"{error_msg}\n{error_details}")
        return False, error_msg
    
    finally:
        # Cerrar conexiones
        try:
            if sftp_client:
                sftp_client.close()
            if ssh_client:
                ssh_client.close()
            logger.debug("Conexiones SSH/SFTP cerradas correctamente")
        except Exception as e:
            logger.warning(f"Error cerrando conexiones: {str(e)}")

def get_remote_files(ssh_config):
    """Obtiene la lista de archivos GSM en el directorio remoto"""
    ssh_client = None
    
    try:
        # Configurar cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        logger.debug(f"Obteniendo archivos remotos de {ssh_config['remote_audio_dir']}")
        
        # Conectar al servidor usando la autenticación apropiada
        if ssh_config['auth_method'] == 'key':
            # Autenticación por clave privada
            ssh_client.connect(
                hostname=ssh_config['ssh_host'],
                port=int(ssh_config['ssh_port']),
                username=ssh_config['ssh_username'],
                key_filename=os.path.expanduser(ssh_config['ssh_key_path']),
                timeout=10
            )
        else:
            # Autenticación por contraseña
            ssh_client.connect(
                hostname=ssh_config['ssh_host'],
                port=int(ssh_config['ssh_port']),
                username=ssh_config['ssh_username'],
                password=ssh_config['ssh_password'],
                timeout=10
            )
        
        # Listar archivos GSM en el directorio
        stdin, stdout, stderr = ssh_client.exec_command(f'ls -l {ssh_config["remote_audio_dir"]}/*.gsm 2>/dev/null || echo "No GSM files found"')
        files_output = stdout.read().decode('utf-8')
        stderr_output = stderr.read().decode('utf-8')
        
        if stderr_output:
            logger.warning(f"Stderr al listar archivos remotos: {stderr_output}")
        
        # Verificar si no hay archivos
        if "No GSM files found" in files_output:
            logger.debug("No se encontraron archivos GSM en el directorio remoto")
            return []
        
        # Procesar la salida
        file_list = []
        for line in files_output.strip().split('\n'):
            if line and not line.startswith("total "):
                try:
                    parts = line.split()
                    if len(parts) >= 9:
                        permissions = parts[0]
                        size = parts[4]
                        date = ' '.join(parts[5:8])
                        filename = ' '.join(parts[8:])  # Por si el nombre tiene espacios
                        file_list.append({
                            'name': os.path.basename(filename),
                            'size': size,
                            'date': date,
                            'permissions': permissions
                        })
                except Exception as e:
                    logger.warning(f"Error procesando línea '{line}': {str(e)}")
        
        logger.debug(f"Se encontraron {len(file_list)} archivos GSM en el servidor")
        return file_list
    
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error listing remote files: {str(e)}\n{error_details}")
        return []
    
    finally:
        if ssh_client:
            ssh_client.close()

def get_local_files():
    """Obtiene la lista de archivos de audio en el directorio local"""
    try:
        local_dir = DEFAULT_CONFIG['local_audio_dir']
        file_list = []
        
        logger.debug(f"Buscando archivos de audio en {local_dir}")
        
        # Extensiones de audio reconocidas
        audio_extensions = ('.wav', '.mp3', '.ogg', '.m4a', '.gsm')
        
        for file in os.listdir(local_dir):
            file_path = os.path.join(local_dir, file)
            if os.path.isfile(file_path) and file.lower().endswith(audio_extensions):
                stats = os.stat(file_path)
                file_list.append({
                    'name': file,
                    'size': stats.st_size,
                    'date': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'path': file_path
                })
        
        logger.debug(f"Se encontraron {len(file_list)} archivos de audio locales")
        return file_list
    
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error listing local files: {str(e)}\n{error_details}")
        return []

def get_ssh_hosts_from_config():
    """Lee el archivo ~/.ssh/config y obtiene los hosts configurados"""
    ssh_config_path = os.path.expanduser('~/.ssh/config')
    hosts = []
    
    try:
        if os.path.exists(ssh_config_path):
            logger.debug(f"Leyendo archivo de configuración SSH: {ssh_config_path}")
            current_host = None
            with open(ssh_config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.lower().startswith('host ') and not '*' in line:
                        current_host = line[5:].strip()
                        if current_host and not current_host.startswith('*'):
                            hosts.append(current_host)
            logger.debug(f"Hosts encontrados en ~/.ssh/config: {hosts}")
            return hosts
        else:
            logger.warning(f"Archivo de configuración SSH no encontrado: {ssh_config_path}")
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error reading SSH config: {str(e)}\n{error_details}")
    
    return hosts

@app.route('/', methods=['GET', 'POST'])
def index():
    """Página principal - Formulario de subida de archivos"""
    form = AudioUploadForm()
    
    # Obtener configuración SSH de la sesión o usar valores predeterminados
    ssh_config = session.get('ssh_config', DEFAULT_CONFIG)
    logger.debug(f"Configuración SSH actual: {ssh_config}")
    
    if form.validate_on_submit():
        logger.info("Formulario enviado, procesando archivo...")
        try:
            # Obtener archivo y nombre limpio
            audio_file = form.audio_file.data
            original_filename = audio_file.filename
            new_filename = secure_filename(form.new_filename.data)
            
            logger.debug(f"Archivo recibido: {original_filename}, nuevo nombre: {new_filename}")
            
            # Guardar archivo temporalmente
            temp_dir = tempfile.mkdtemp()
            temp_input_path = os.path.join(temp_dir, secure_filename(original_filename))
            audio_file.save(temp_input_path)
            
            logger.debug(f"Archivo guardado temporalmente en: {temp_input_path}")
            
            # También guardar en el directorio local de audios
            local_path = os.path.join(DEFAULT_CONFIG['local_audio_dir'], secure_filename(original_filename))
            audio_file.seek(0)  # Reset file pointer
            with open(local_path, 'wb') as f:
                f.write(audio_file.read())
            
            logger.debug(f"Copia guardada en directorio local: {local_path}")
                
            # Convertir a GSM
            gsm_filename = f"{new_filename}.gsm"
            temp_output_path = os.path.join(temp_dir, gsm_filename)
            
            logger.info(f"Iniciando conversión a GSM: {temp_input_path} -> {temp_output_path}")
            conversion_success, conversion_error = convert_to_gsm(temp_input_path, temp_output_path)
            
            if conversion_success:
                logger.info("Conversión a GSM exitosa")
                
                # Verificar configuración SSH
                if ssh_config['auth_method'] == 'password' and not ssh_config['ssh_password']:
                    logger.warning("Falta contraseña para autenticación SSH")
                    flash('Por favor, configure los datos de conexión SSH primero', 'warning')
                    return redirect(url_for('config'))
                
                if ssh_config['auth_method'] == 'key':
                    key_path = os.path.expanduser(ssh_config['ssh_key_path'])
                    if not os.path.isfile(key_path):
                        logger.error(f"La clave SSH no existe: {key_path}")
                        flash(f"La clave SSH no existe en {ssh_config['ssh_key_path']}", 'danger')
                        return redirect(url_for('config'))
                
                # Ruta completa en el servidor remoto
                remote_path = f"{ssh_config['remote_audio_dir']}/{gsm_filename}"
                
                # Subir archivo al servidor
                logger.info(f"Iniciando subida al servidor: {temp_output_path} -> {remote_path}")
                upload_success, upload_error = upload_file_to_server(temp_output_path, remote_path, ssh_config)
                
                if upload_success:
                    logger.info(f"Archivo {gsm_filename} subido exitosamente al servidor")
                    flash(f'Archivo {gsm_filename} subido exitosamente al servidor', 'success')
                else:
                    logger.error(f"Error al subir el archivo: {upload_error}")
                    flash(f'Error al subir el archivo al servidor: {upload_error}', 'danger')
            else:
                logger.error(f"Error al convertir el archivo: {conversion_error}")
                flash(f'Error al convertir el archivo a formato GSM: {conversion_error}', 'danger')
                
            # Limpiar archivos temporales
            try:
                logger.debug(f"Limpiando archivos temporales en {temp_dir}")
                os.remove(temp_input_path)
                os.remove(temp_output_path)
                os.rmdir(temp_dir)
            except Exception as e:
                logger.warning(f"Error limpiando archivos temporales: {str(e)}")
                
            return redirect(url_for('index'))
            
        except Exception as e:
            error_details = traceback.format_exc()
            logger.error(f"Error processing upload: {str(e)}\n{error_details}")
            flash(f'Error: {str(e)}', 'danger')
    
    # Obtener listas de archivos
    local_files = get_local_files()
    remote_files = []
    
    # Solo intentar obtener archivos remotos si tenemos configuración válida
    if ssh_config['auth_method'] == 'key' and os.path.isfile(os.path.expanduser(ssh_config['ssh_key_path'])):
        logger.debug("Obteniendo archivos remotos usando autenticación por clave")
        remote_files = get_remote_files(ssh_config)
    elif ssh_config['auth_method'] == 'password' and ssh_config['ssh_password']:
        logger.debug("Obteniendo archivos remotos usando autenticación por contraseña")
        remote_files = get_remote_files(ssh_config)
    else:
        logger.debug("No se pueden obtener archivos remotos: configuración de autenticación incompleta")
    
    return render_template(
        'index.html', 
        form=form, 
        local_files=local_files,
        remote_files=remote_files,
        ssh_config=ssh_config
    )

@app.route('/config', methods=['GET', 'POST'])
def config():
    """Página de configuración SSH"""
    form = SSHConfigForm()
    
    # Obtener los hosts del archivo ~/.ssh/config
    ssh_hosts = get_ssh_hosts_from_config()
    
    if form.validate_on_submit():
        logger.info("Formulario de configuración enviado, procesando...")
        # Guardar configuración en la sesión
        ssh_config = {
            'ssh_host': form.ssh_host.data,
            'ssh_port': form.ssh_port.data,
            'ssh_username': form.ssh_username.data,
            'auth_method': form.auth_method.data,
            'ssh_password': form.ssh_password.data if form.auth_method.data == 'password' else '',
            'ssh_key_path': form.ssh_key_path.data if form.auth_method.data == 'key' else '',
            'remote_audio_dir': form.remote_dir.data
        }
        
        logger.debug(f"Nueva configuración SSH: {ssh_config}")
        
        # Guardar en sesión
        session['ssh_config'] = ssh_config
        
        # Intentar conexión de prueba
        try:
            logger.info(f"Probando conexión SSH a {ssh_config['ssh_host']}:{ssh_config['ssh_port']}")
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_config['auth_method'] == 'key':
                key_path = os.path.expanduser(ssh_config['ssh_key_path'])
                if not os.path.isfile(key_path):
                    logger.error(f"La clave SSH no existe: {key_path}")
                    flash(f"La clave SSH no existe en {ssh_config['ssh_key_path']}", 'danger')
                    return render_template('config.html', form=form, ssh_hosts=ssh_hosts)
                
                logger.debug(f"Intentando conexión con clave: {key_path}")
                ssh_client.connect(
                    hostname=ssh_config['ssh_host'],
                    port=int(ssh_config['ssh_port']),
                    username=ssh_config['ssh_username'],
                    key_filename=key_path,
                    timeout=5
                )
            else:
                logger.debug("Intentando conexión con contraseña")
                ssh_client.connect(
                    hostname=ssh_config['ssh_host'],
                    port=int(ssh_config['ssh_port']),
                    username=ssh_config['ssh_username'],
                    password=ssh_config['ssh_password'],
                    timeout=5
                )
            
            # Probar acceso al directorio remoto
            try:
                logger.debug(f"Verificando acceso al directorio remoto: {ssh_config['remote_audio_dir']}")
                stdin, stdout, stderr = ssh_client.exec_command(f"ls -la {ssh_config['remote_audio_dir']}")
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    error = stderr.read().decode('utf-8')
                    logger.error(f"No se puede acceder al directorio remoto: {error}")
                    flash(f"No se puede acceder al directorio remoto: {error}", 'warning')
                else:
                    logger.debug("Acceso al directorio remoto verificado")
            except Exception as e:
                logger.warning(f"Error verificando directorio remoto: {str(e)}")
                flash(f"Advertencia: No se pudo verificar el acceso al directorio remoto", 'warning')
            
            # Probar sudo
            try:
                logger.debug("Verificando permisos sudo")
                stdin, stdout, stderr = ssh_client.exec_command("sudo -n true")
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    error = stderr.read().decode('utf-8')
                    logger.warning(f"Problemas con sudo: {error}")
                    if "password is required" in error or "no tty present" in error:
                        flash("Advertencia: El comando sudo requiere contraseña. Configure sudo NOPASSWD para el usuario.", 'warning')
            except Exception as e:
                logger.warning(f"Error verificando sudo: {str(e)}")
            
            ssh_client.close()
            
            logger.info("Conexión SSH exitosa")
            flash('Conexión SSH exitosa', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            error_details = traceback.format_exc()
            logger.error(f"Error de conexión SSH: {str(e)}\n{error_details}")
            flash(f'Error de conexión SSH: {str(e)}', 'danger')
    else:
        # Cargar configuración de la sesión si existe
        if 'ssh_config' in session:
            logger.debug("Cargando configuración SSH desde sesión")
            form.ssh_host.data = session['ssh_config']['ssh_host']
            form.ssh_port.data = session['ssh_config']['ssh_port']
            form.ssh_username.data = session['ssh_config']['ssh_username']
            form.auth_method.data = session['ssh_config']['auth_method']
            form.ssh_key_path.data = session['ssh_config']['ssh_key_path']
            form.remote_dir.data = session['ssh_config']['remote_audio_dir']
    
    return render_template('config.html', form=form, ssh_hosts=ssh_hosts)

@app.route('/load_ssh_host/<host>', methods=['GET'])
def load_ssh_host(host):
    """Carga datos de un host desde ~/.ssh/config"""
    ssh_config_path = os.path.expanduser('~/.ssh/config')
    result = {
        'found': False,
        'host': host,
        'hostname': '',
        'port': 22,
        'username': '',
        'key_path': ''
    }
    
    logger.debug(f"Buscando configuración para host '{host}' en {ssh_config_path}")
    
    try:
        if os.path.exists(ssh_config_path):
            current_host = None
            host_data = {}
            
            with open(ssh_config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    if line.lower().startswith('host '):
                        if host_data and current_host == host:
                            result.update(host_data)
                            result['found'] = True
                            break
                        
                        current_host = line[5:].strip()
                        host_data = {}
                    
                    elif current_host == host:
                        logger.debug(f"Encontrada línea de configuración para {host}: {line}")
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            host_data[key] = value
                        elif ' ' in line:
                            parts = line.split(' ', 1)
                            key = parts[0].strip().lower()
                            value = parts[1].strip()
                            
                            if key == 'hostname':
                                host_data['hostname'] = value
                            elif key == 'user':
                                host_data['username'] = value
                            elif key == 'port':
                                host_data['port'] = value
                            elif key == 'identityfile':
                                host_data['key_path'] = value.replace('~', os.path.expanduser('~'))
            
            # Verificar el último host del archivo
            if host_data and current_host == host:
                result.update(host_data)
                result['found'] = True
                
            logger.debug(f"Resultado de la búsqueda para host '{host}': {result}")
                
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error reading SSH config for {host}: {str(e)}\n{error_details}")
    
    return jsonify(result)

@app.route('/test_ffmpeg', methods=['GET'])
def test_ffmpeg():
    """Comprueba si ffmpeg está instalado correctamente"""
    try:
        logger.debug("Verificando instalación de ffmpeg")
        process = subprocess.run(['ffmpeg', '-version'], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                text=True)
        if process.returncode == 0:
            version = process.stdout.split('\n')[0]
            logger.info(f"ffmpeg instalado: {version}")
            return jsonify({'status': 'ok', 'message': f'ffmpeg instalado: {version}'})
        else:
            error = process.stderr
            logger.error(f"ffmpeg no encontrado o error: {error}")
            return jsonify({'status': 'error', 'message': f'ffmpeg no encontrado o error: {error}'})
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error verificando ffmpeg: {str(e)}\n{error_details}")
        return jsonify({'status': 'error', 'message': f'ffmpeg no está instalado: {str(e)}'})

@app.route('/test_sudo', methods=['GET'])
def test_sudo():
    """Comprueba si se puede ejecutar sudo sin contraseña en el servidor"""
    ssh_config = session.get('ssh_config', DEFAULT_CONFIG)
    
    try:
        logger.debug(f"Verificando permisos sudo en {ssh_config['ssh_host']}")
        
        # Configurar cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        if ssh_config['auth_method'] == 'key':
            ssh_client.connect(
                hostname=ssh_config['ssh_host'],
                port=int(ssh_config['ssh_port']),
                username=ssh_config['ssh_username'],
                key_filename=os.path.expanduser(ssh_config['ssh_key_path']),
                timeout=5
            )
        else:
            ssh_client.connect(
                hostname=ssh_config['ssh_host'],
                port=int(ssh_config['ssh_port']),
                username=ssh_config['ssh_username'],
                password=ssh_config['ssh_password'],
                timeout=5
            )
        
        # Probar sudo
        stdin, stdout, stderr = ssh_client.exec_command("sudo -n chown omar:omar /tmp/sudo_test_file 2>&1 || echo 'SUDO_ERROR'")
        output = stdout.read().decode('utf-8')
        
        ssh_client.close()
        
        if "SUDO_ERROR" in output:
            if "no tty present and no askpass program specified" in output:
                logger.error("Sudo requiere contraseña")
                return jsonify({
                    'status': 'error', 
                    'message': 'El comando sudo requiere contraseña. Configure sudo NOPASSWD para el usuario.'
                })
            else:
                logger.error(f"Error con sudo: {output}")
                return jsonify({
                    'status': 'error',
                    'message': f'Error al ejecutar sudo: {output}'
                })
        else:
            logger.info("Sudo funciona correctamente")
            return jsonify({
                'status': 'ok',
                'message': 'Sudo funciona correctamente sin contraseña'
            })
            
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error verificando sudo: {str(e)}\n{error_details}")
        return jsonify({
            'status': 'error',
            'message': f'Error de conexión: {str(e)}'
        })

@app.route('/test_upload', methods=['GET'])
def test_upload():
    """Realiza una prueba de subida de un archivo pequeño"""
    ssh_config = session.get('ssh_config', DEFAULT_CONFIG)
    
    try:
        logger.debug(f"Realizando prueba de subida a {ssh_config['ssh_host']}")
        
        # Crear archivo temporal
        temp_dir = tempfile.mkdtemp()
        test_file_path = os.path.join(temp_dir, "test_upload.txt")
        with open(test_file_path, 'w') as f:
            f.write("Este es un archivo de prueba para verificar la subida.")
        
        # Ruta en el servidor
        remote_path = f"/tmp/test_upload_{int(datetime.now().timestamp())}.txt"
        
        # Subir archivo
        upload_success, upload_error = upload_file_to_server(test_file_path, remote_path, ssh_config)
        
        # Limpiar
        try:
            os.remove(test_file_path)
            os.rmdir(temp_dir)
        except:
            pass
        
        if upload_success:
            logger.info(f"Prueba de subida exitosa: {remote_path}")
            return jsonify({
                'status': 'ok',
                'message': f'Archivo subido correctamente a {remote_path}'
            })
        else:
            logger.error(f"Error en prueba de subida: {upload_error}")
            return jsonify({
                'status': 'error',
                'message': f'Error al subir archivo: {upload_error}'
            })
            
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error en prueba de subida: {str(e)}\n{error_details}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        })

@app.route('/server_info', methods=['GET'])
def server_info():
    """Obtiene información del servidor"""
    ssh_config = session.get('ssh_config', DEFAULT_CONFIG)
    
    try:
        logger.debug(f"Obteniendo información del servidor {ssh_config['ssh_host']}")
        
        # Configurar cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        if ssh_config['auth_method'] == 'key':
            ssh_client.connect(
                hostname=ssh_config['ssh_host'],
                port=int(ssh_config['ssh_port']),
                username=ssh_config['ssh_username'],
                key_filename=os.path.expanduser(ssh_config['ssh_key_path']),
                timeout=5
            )
        else:
            ssh_client.connect(
                hostname=ssh_config['ssh_host'],
                port=int(ssh_config['ssh_port']),
                username=ssh_config['ssh_username'],
                password=ssh_config['ssh_password'],
                timeout=5
            )
        
        # Obtener información del sistema
        info = {}
        
        # Sistema operativo
        stdin, stdout, stderr = ssh_client.exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2")
        info['os'] = stdout.read().decode('utf-8').strip().replace('"', '')
        
        # Espacio en disco
        stdin, stdout, stderr = ssh_client.exec_command(f"df -h {ssh_config['remote_audio_dir']} | tail -1")
        df_output = stdout.read().decode('utf-8').strip()
        info['disk'] = ' '.join(df_output.split()[1:5]) if df_output else "No disponible"
        
        # Verificar directorio de audio
        stdin, stdout, stderr = ssh_client.exec_command(f"ls -ld {ssh_config['remote_audio_dir']}")
        dir_output = stdout.read().decode('utf-8').strip()
        info['audio_dir'] = dir_output if dir_output else "No disponible"
        
        # Verificar permisos
        stdin, stdout, stderr = ssh_client.exec_command("groups")
        groups = stdout.read().decode('utf-8').strip()
        info['groups'] = groups
        
        # Comprobar sudo
        stdin, stdout, stderr = ssh_client.exec_command("sudo -n -l 2>/dev/null || echo 'Sudo requiere contraseña'")
        sudo_output = stdout.read().decode('utf-8').strip()
        info['sudo'] = sudo_output
        
        ssh_client.close()
        
        logger.info(f"Información del servidor obtenida: {info}")
        return jsonify({
            'status': 'ok',
            'info': info
        })
            
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error obteniendo información del servidor: {str(e)}\n{error_details}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        })

if __name__ == '__main__':
    try:
        # Verificar ffmpeg al inicio
        logger.info("Iniciando Asterisk Audio Uploader")
        logger.info("Verificando ffmpeg...")
        
        process = subprocess.run(['ffmpeg', '-version'], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
        if process.returncode != 0:
            logger.warning("ffmpeg no está instalado o no se encuentra en el PATH")
            print("ADVERTENCIA: ffmpeg no encontrado. Por favor, instale ffmpeg para poder convertir archivos.")
        else:
            version = process.stdout.decode('utf-8').split('\n')[0]
            logger.info(f"ffmpeg detectado: {version}")
            print(f"ffmpeg detectado: {version}")
        
        # Verificar directorio de audios
        audio_dir = os.path.expanduser(DEFAULT_CONFIG['local_audio_dir'])
        if not os.path.exists(audio_dir):
            os.makedirs(audio_dir)
            logger.info(f"Directorio de audios creado: {audio_dir}")
        
        # Verificar configuración SSH
        ssh_config_path = os.path.expanduser('~/.ssh/config')
        if os.path.exists(ssh_config_path):
            logger.info(f"Configuración SSH encontrada: {ssh_config_path}")
            hosts = get_ssh_hosts_from_config()
            if hosts:
                logger.info(f"Hosts SSH configurados: {', '.join(hosts)}")
        else:
            logger.warning(f"Archivo de configuración SSH no encontrado: {ssh_config_path}")
        
        # Iniciar aplicación
        logger.info("Iniciando servidor web en http://0.0.0.0:5000")
        print("Iniciando servidor web en http://0.0.0.0:5000")
        app.run(debug=True, host='0.0.0.0', port=5000)
        
    except Exception as e:
        error_details = traceback.format_exc()
        logger.error(f"Error al iniciar la aplicación: {str(e)}\n{error_details}")
        print(f"ERROR: No se pudo iniciar la aplicación: {str(e)}")