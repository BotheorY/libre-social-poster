from flask import Flask, Response, request, jsonify, render_template, redirect, url_for
import sys
import os
import uuid
import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import pymysql
from pymysql.cursors import DictCursor
from datetime import datetime
import pytz

app = Flask(__name__)
DEBUG_MODE = True
LOCAL_FOLDER_PATH = '/home/botheory/fracassi/'

# Carica configurazioni AWS
with open(LOCAL_FOLDER_PATH + 'assets/aws_config.json') as f:
    aws_config = json.load(f)

AWS_ACCESS_KEY_ID = aws_config['aws_access_key_id']
AWS_SECRET_ACCESS_KEY = aws_config['aws_secret_access_key']
AWS_REGION = aws_config['region_name']
S3_BUCKET = aws_config['s3_bucket']

# Carica configurazioni Database
with open(LOCAL_FOLDER_PATH + 'assets/db_config.json') as f:
    db_config = json.load(f)

DB_HOST = db_config['host']
DB_USER = db_config['user']
DB_PASSWORD = db_config['password']
DB_NAME = db_config['database']

# Inizializza client S3
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

# Sessioni di upload in memoria
upload_sessions = {}

# Dimensione del chunk (es. 5MB)
CHUNK_SIZE = 5 * 1024 * 1024

@app.route('/api/s3send', methods=['PUT'])
def api_s3send():
    try:
        # Estrai parametri dalla richiesta
        upload_uuid = request.form.get('upload_uuid')
        file_part = request.files.get('file_part')
        part_number = int(request.form.get('part_number'))
        file_name = request.form.get('file_name')
        file_size = int(request.form.get('file_size', 0))  # Solo nel primo chunk

        if not file_part or not part_number or not file_name:
            return jsonify({'error': 'Parametri mancanti'}), 400

        if not upload_uuid:
            # Inizio di un nuovo upload
            upload_uuid = str(uuid.uuid4())

            # Inizia multipart upload
            response = s3_client.create_multipart_upload(
                Bucket=S3_BUCKET,
                Key=file_name
            )
            upload_id = response['UploadId']

            # Salva sessione in memoria
            upload_sessions[upload_uuid] = {
                'upload_id': upload_id,
                'file_name': file_name,
                'file_size': file_size,
                'uploaded_bytes': 0,
                'parts': {}
            }

            save_log(f"[100] upload_sessions = {upload_sessions}")  # DEBUG

            # Inserisci record nel database
            conn = get_db_connection()
            with conn.cursor() as cursor:
                sql = """
                    INSERT INTO s3_progress (upload_uuid, prg_status, progress)
                    VALUES (%s, %s, %s)
                """
                cursor.execute(sql, (upload_uuid, 'PROGRESS', 0))
            conn.close()
        else:
            # Recupera sessione esistente
            if upload_uuid not in upload_sessions:
                return jsonify({'error': f"Upload UUID '{upload_uuid}' (upload_sessions = {upload_sessions}) non valido"}), 400
            upload_id = upload_sessions[upload_uuid]['upload_id']

        # Carica la parte su S3
        response = s3_client.upload_part(
            Bucket=S3_BUCKET,
            Key=file_name,
            PartNumber=part_number,
            UploadId=upload_id,
            Body=file_part.stream
        )
        etag = response['ETag']

        # Aggiorna sessione in memoria
        session = upload_sessions[upload_uuid]

        save_log(f"[200] upload_sessions = {upload_sessions}")  # DEBUG
        
        session['parts'][part_number] = etag
        session['uploaded_bytes'] += len(file_part.read())

        # Calcola progresso
        if session['file_size'] > 0:
            progress = int((session['uploaded_bytes'] / session['file_size']) * 100)
            progress = min(progress, 100)
        else:
            progress = 0

        # Aggiorna database
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = """
                UPDATE s3_progress
                SET progress = %s
                WHERE upload_uuid = %s
            """
            cursor.execute(sql, (progress, upload_uuid))
        conn.close()

        # Verifica se l'upload è completo
        if session['uploaded_bytes'] >= session['file_size']:
            # Completa multipart upload
            parts = [{'ETag': etag, 'PartNumber': num} for num, etag in sorted(session['parts'].items())]
            s3_client.complete_multipart_upload(
                Bucket=S3_BUCKET,
                Key=file_name,
                UploadId=upload_id,
                MultipartUpload={'Parts': parts}
            )
            # Ottieni URL del file
            file_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{file_name}"

            # Aggiorna database con stato completato
            conn = get_db_connection()
            with conn.cursor() as cursor:
                sql = """
                    UPDATE s3_progress
                    SET prg_status = %s, progress = %s, s3_file_url = %s
                    WHERE upload_uuid = %s
                """
                cursor.execute(sql, ('COMPLETED', 100, file_url, upload_uuid))
            conn.close()

            # Rimuovi sessione in memoria

            save_log(f"[300] upload_sessions = {upload_sessions}")  # DEBUG
            
            del upload_sessions[upload_uuid]

            save_log(f"[400] upload_sessions = {upload_sessions}")  # DEBUG

        return jsonify({'upload_uuid': upload_uuid}), 200

    except (BotoCoreError, ClientError) as e:
        # Gestione errori S3
        if upload_uuid and upload_uuid in upload_sessions:
            # Aggiorna database con stato di errore
            conn = get_db_connection()
            with conn.cursor() as cursor:
                sql = """
                    UPDATE s3_progress
                    SET prg_status = %s, err_code = %s, err_msg = %s
                    WHERE upload_uuid = %s
                """
                cursor.execute(sql, ('ERROR', 500, str(e), upload_uuid))
            conn.close()
            del upload_sessions[upload_uuid]
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        # Gestione errori generici
        if upload_uuid and upload_uuid in upload_sessions:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                sql = """
                    UPDATE s3_progress
                    SET prg_status = %s, err_code = %s, err_msg = %s
                    WHERE upload_uuid = %s
                """
                cursor.execute(sql, ('ERROR', 500, str(e), upload_uuid))
            conn.close()
            del upload_sessions[upload_uuid]
        return jsonify({'error': str(e)}), 500

@app.route('/api/s3progress', methods=['GET'])
def api_s3progress():
    upload_uuid = request.args.get('upload_uuid')
    if not upload_uuid:
        return jsonify({'error': 'Parametri mancanti'}), 400

    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            sql = """
                SELECT prg_status, progress, err_code, err_msg, s3_file_url
                FROM s3_progress
                WHERE upload_uuid = %s
            """
            cursor.execute(sql, (upload_uuid,))
            result = cursor.fetchone()
        conn.close()

        if not result:
            return jsonify({'error': 'Upload UUID non trovato'}), 404

        return jsonify(result), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def home():    
    return redirect(url_for('socialpub', _external=True))

@app.route('/socialpub')
@app.route('/socialpub/')
def socialpub():    
    return redirect(url_for('ytpub', _external=True))

@app.route('/ytpub')
@app.route('/ytpub/')
def ytpub():
    
    try:
        return render_template('ytpub.html', 
                            is_authenticated=True,
                            categories=[],
                            year=2024)
    except Exception as e:
        if DEBUG_MODE:
            exc_type, exc_obj, tb = sys.exc_info()
            f_name = tb.tb_frame.f_code.co_filename
            line_no = tb.tb_lineno
            err = '[' + type(e).__name__ + '] [' + f_name + ', ' + str(line_no) + '] ' + str(e)
        else:
            err = '[' + type(e).__name__ + '] ' + str(e)
        return err, 500

@app.route('/ytclearauth')
def ytclearauth():
    return 'OK', 200

@app.route('/api')
@app.route('/api/')
def api():    
    return redirect(url_for('home', _external=True))

@app.route('/robots.txt')
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype='text/plain')

@app.route('/s3upload')
@app.route('/s3upload/')
def s3upload():
    
    try:
        return render_template('s3upload.html', year=datetime.now().year)
    except Exception as e:
        if DEBUG_MODE:
            exc_type, exc_obj, tb = sys.exc_info()
            f_name = tb.tb_frame.f_code.co_filename
            line_no = tb.tb_lineno
            err = '[' + type(e).__name__ + '] [' + f_name + ', ' + str(line_no) + '] ' + str(e)
        else:
            err = '[' + type(e).__name__ + '] ' + str(e)
        return err, 500

# Connessione al database
def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=DictCursor,
        autocommit=True
    )

def save_log(text: str):

    def rome_datetime():
        fuso_orario_roma = pytz.timezone('Europe/Rome')
        data_ora_roma = datetime.now(fuso_orario_roma)
        return data_ora_roma.strftime('%Y-%m-%d %H:%M:%S')

    text = f"[{rome_datetime()}] {text}\n"
    with open(LOCAL_FOLDER_PATH + 'log.txt', 'a', encoding='utf-8') as file:
        file.write(text)
