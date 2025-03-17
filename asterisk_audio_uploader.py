#!/usr/bin/env python3
"""
Asterisk Audio Uploader
-----------------------
Una aplicación web que permite subir archivos de audio al servidor Asterisk,
convirtiendo automáticamente los archivos a formato GSM y colocándolos
en la ruta correcta.

Requisitos:
- pip install flask paramiko pydub flask-wtf
- ffmpeg debe estar instalado en el sistema local
"""

import os
import tempfile
import subprocess
import logging
from pathlib import Path
from datetime import datetime

import paramiko
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
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
    ssh_password = PasswordField('Contraseña SSH', validators=[DataRequired()])
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
            return False
        
        logger.info(f"Successfully converted {input_file} to GSM format")
        return True
    
    except Exception as e:
        logger.error(f"Exception during conversion: {str(e)}")
        return False

def upload_file_to_server(local_file, remote_file, ssh_config):
    """Sube un archivo al servidor remoto mediante SSH/SCP"""
    ssh_client = None
    sftp_client = None
    
    try:
        # Configurar cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=ssh_config['ssh_host'],
            port=int(ssh_config['ssh_port']),
            username=ssh_config['ssh_username'],
            password=ssh_config['ssh_password'],
            timeout=10
        )
        
        # Transferir archivo
        sftp_client = ssh_client.open_sftp()
        sftp_client.put(local_file, remote_file)
        
        # Establecer permisos apropiados
        sftp_client.chmod(remote_file, 0o644)
        
        # Ejecutar comando para cambiar el propietario a asterisk:asterisk
        ssh_client.exec_command(f'sudo chown asterisk:asterisk "{remote_file}"')
        
        logger.info(f"Successfully uploaded {local_file} to {remote_file}")
        return True
    
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        return False
    
    finally:
        # Cerrar conexiones
        if sftp_client:
            sftp_client.close()
        if ssh_client:
            ssh_client.close()

def get_remote_files(ssh_config):
    """Obtiene la lista de archivos GSM en el directorio remoto"""
    ssh_client = None
    
    try:
        # Configurar cliente SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Conectar al servidor
        ssh_client.connect(
            hostname=ssh_config['ssh_host'],
            port=int(ssh_config['ssh_port']),
            username=ssh_config['ssh_username'],
            password=ssh_config['ssh_password'],
            timeout=10
        )
        
        # Listar archivos GSM en el directorio
        stdin, stdout, stderr = ssh_client.exec_command(f'ls -l {ssh_config["remote_audio_dir"]}/*.gsm')
        files_output = stdout.read().decode('utf-8')
        
        # Procesar la salida
        file_list = []
        for line in files_output.strip().split('\n'):
            if line:
                parts = line.split()
                if len(parts) >= 9:
                    permissions = parts[0]
                    size = parts[4]
                    date = ' '.join(parts[5:8])
                    filename = parts[8]
                    file_list.append({
                        'name': os.path.basename(filename),
                        'size': size,
                        'date': date,
                        'permissions': permissions
                    })
        
        return file_list
    
    except Exception as e:
        logger.error(f"Error listing remote files: {str(e)}")
        return []
    
    finally:
        if ssh_client:
            ssh_client.close()

def get_local_files():
    """Obtiene la lista de archivos de audio en el directorio local"""
    try:
        local_dir = DEFAULT_CONFIG['local_audio_dir']
        file_list = []
        
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
        
        return file_list
    
    except Exception as e:
        logger.error(f"Error listing local files: {str(e)}")
        return []

@app.route('/', methods=['GET', 'POST'])
def index():
    """Página principal - Formulario de subida de archivos"""
    form = AudioUploadForm()
    
    if form.validate_on_submit():
        try:
            # Obtener archivo y nombre limpio
            audio_file = form.audio_file.data
            new_filename = secure_filename(form.new_filename.data)
            
            # Guardar archivo temporalmente
            temp_dir = tempfile.mkdtemp()
            temp_input_path = os.path.join(temp_dir, secure_filename(audio_file.filename))
            audio_file.save(temp_input_path)
            
            # También guardar en el directorio local de audios
            local_path = os.path.join(DEFAULT_CONFIG['local_audio_dir'], secure_filename(audio_file.filename))
            audio_file.seek(0)  # Reset file pointer
            with open(local_path, 'wb') as f:
                f.write(audio_file.read())
                
            # Convertir a GSM
            gsm_filename = f"{new_filename}.gsm"
            temp_output_path = os.path.join(temp_dir, gsm_filename)
            
            if convert_to_gsm(temp_input_path, temp_output_path):
                # Obtener configuración SSH de la sesión o usar valores predeterminados
                ssh_config = {
                    'ssh_host': request.form.get('ssh_host', DEFAULT_CONFIG['ssh_host']),
                    'ssh_port': request.form.get('ssh_port', DEFAULT_CONFIG['ssh_port']),
                    'ssh_username': request.form.get('ssh_username', DEFAULT_CONFIG['ssh_username']),
                    'ssh_password': request.form.get('ssh_password', ''),
                    'remote_audio_dir': request.form.get('remote_dir', DEFAULT_CONFIG['remote_audio_dir'])
                }
                
                # Si no hay contraseña, redirigir a configuración
                if not ssh_config['ssh_password']:
                    flash('Por favor, configure los datos de conexión SSH primero', 'warning')
                    return redirect(url_for('config'))
                
                # Ruta completa en el servidor remoto
                remote_path = f"{ssh_config['remote_audio_dir']}/{gsm_filename}"
                
                # Subir archivo al servidor
                if upload_file_to_server(temp_output_path, remote_path, ssh_config):
                    flash(f'Archivo {gsm_filename} subido exitosamente al servidor', 'success')
                else:
                    flash('Error al subir el archivo al servidor', 'danger')
            else:
                flash('Error al convertir el archivo a formato GSM', 'danger')
                
            # Limpiar archivos temporales
            try:
                os.remove(temp_input_path)
                os.remove(temp_output_path)
                os.rmdir(temp_dir)
            except:
                pass
                
            return redirect(url_for('index'))
            
        except Exception as e:
            logger.error(f"Error processing upload: {str(e)}")
            flash(f'Error: {str(e)}', 'danger')
    
    # Obtener listas de archivos (solo intentar remotos si hay credenciales)
    local_files = get_local_files()
    remote_files = []
    
    ssh_config = {
        'ssh_host': request.form.get('ssh_host', DEFAULT_CONFIG['ssh_host']),
        'ssh_port': request.form.get('ssh_port', DEFAULT_CONFIG['ssh_port']),
        'ssh_username': request.form.get('ssh_username', DEFAULT_CONFIG['ssh_username']),
        'ssh_password': request.form.get('ssh_password', ''),
        'remote_audio_dir': request.form.get('remote_dir', DEFAULT_CONFIG['remote_audio_dir'])
    }
    
    if ssh_config['ssh_password']:
        remote_files = get_remote_files(ssh_config)
    
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
    
    if form.validate_on_submit():
        # Guardar configuración en la sesión
        ssh_config = {
            'ssh_host': form.ssh_host.data,
            'ssh_port': form.ssh_port.data,
            'ssh_username': form.ssh_username.data,
            'ssh_password': form.ssh_password.data,
            'remote_audio_dir': form.remote_dir.data
        }
        
        # Intentar conexión de prueba
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=ssh_config['ssh_host'],
                port=int(ssh_config['ssh_port']),
                username=ssh_config['ssh_username'],
                password=ssh_config['ssh_password'],
                timeout=5
            )
            ssh_client.close()
            
            flash('Conexión SSH exitosa', 'success')
            
            # Redirigir a la página principal con los parámetros
            return redirect(url_for('index', 
                                   ssh_host=ssh_config['ssh_host'],
                                   ssh_port=ssh_config['ssh_port'],
                                   ssh_username=ssh_config['ssh_username'],
                                   ssh_password=ssh_config['ssh_password'],
                                   remote_dir=ssh_config['remote_audio_dir']))
            
        except Exception as e:
            flash(f'Error de conexión SSH: {str(e)}', 'danger')
    
    return render_template('config.html', form=form)

@app.route('/test_ffmpeg', methods=['GET'])
def test_ffmpeg():
    """Comprueba si ffmpeg está instalado correctamente"""
    try:
        process = subprocess.run(['ffmpeg', '-version'], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                text=True)
        if process.returncode == 0:
            version = process.stdout.split('\n')[0]
            return jsonify({'status': 'ok', 'message': f'ffmpeg instalado: {version}'})
        else:
            return jsonify({'status': 'error', 'message': 'ffmpeg no encontrado o error'})
    except:
        return jsonify({'status': 'error', 'message': 'ffmpeg no está instalado'})

if __name__ == '__main__':
    try:
        # Verificar ffmpeg al inicio
        process = subprocess.run(['ffmpeg', '-version'], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
        if process.returncode != 0:
            logger.warning("ffmpeg no está instalado o no se encuentra en el PATH")
            print("ADVERTENCIA: ffmpeg no encontrado. Por favor, instale ffmpeg para poder convertir archivos.")
    except:
        logger.error("Error al verificar ffmpeg")
        print("ERROR: No se puede ejecutar ffmpeg. Por favor, instale ffmpeg para poder convertir archivos.")
    
    # Iniciar aplicación
    app.run(debug=True, host='0.0.0.0', port=5000)