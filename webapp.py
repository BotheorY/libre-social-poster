import os
import io
import json
import uuid
import math
from flask import Flask, Response, request, jsonify, redirect, url_for, render_template
import mysql.connector
import boto3
from datetime import datetime
import sys
import pytz

app = Flask(__name__)
DEBUG_MODE = True
LOCAL_FOLDER_PATH = '/home/botheory/fracassi/'

# ------------------------------------------------
# Lettura credenziali AWS da file JSON
# ------------------------------------------------
with open(LOCAL_FOLDER_PATH + 'assets/aws_config.json', 'r') as f:
    aws_config = json.load(f)

AWS_ACCESS_KEY = aws_config['aws_access_key_id']
AWS_SECRET_KEY = aws_config['aws_secret_access_key']
AWS_REGION = aws_config['aws_region']
S3_BUCKET_NAME = aws_config['s3_bucket_name']

# Creazione client boto3
s3_client = boto3.client(
    's3',
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY
)

# ------------------------------------------------
# Lettura credenziali DB MySQL da file JSON
# ------------------------------------------------
with open(LOCAL_FOLDER_PATH + 'assets/db_config.json', 'r') as f:
    db_conf = json.load(f)

DB_HOST = db_conf['host']
DB_PORT = db_conf['port']
DB_NAME = db_conf['database']
DB_USER = db_conf['user']
DB_PASS = db_conf['password']

# Sessioni di upload in memoria
upload_sessions = {}

# Dimensione del chunk (es. 5MB)
CHUNK_SIZE = 5 * 1024 * 1024

@app.route('/api/s3send', methods=['PUT'])
def api_s3send():
    """
    Riceve il file via PUT, lo carica su S3 in modalità streaming a chunk,
    aggiorna la tabella s3_progress su MySQL e restituisce un UUID.
    """
    # Generiamo un nuovo UUID per questa operazione di upload
    upload_uuid = str(uuid.uuid4())

    # Preparazione tabella: inserimento riga con PROGRESS
    cnx = get_db_connection()
    cursor = cnx.cursor()
    insert_stmt = """
        INSERT INTO s3_progress (upload_uuid, prg_status, progress)
        VALUES (%s, 'PROGRESS', 0)
    """
    cursor.execute(insert_stmt, (upload_uuid,))
    cnx.commit()

    # Inizializziamo una multi-part upload su S3
    try:
        create_mpu = s3_client.create_multipart_upload(Bucket=S3_BUCKET_NAME,
                                                       Key=f'upload_{upload_uuid}')
        upload_id = create_mpu['UploadId']

        part_number = 1
        parts = []

        # Leggiamo lo stream della request in chunk
        chunk_size = 5 * 1024 * 1024  # 5 MB come esempio
        total_bytes_uploaded = 0

        # Per calcolare la dimensione totale, possiamo tentare di leggere l'header Content-Length,
        # se presente. Se non c'è, si può aggiornare la percentuale in base ai chunk inviati,
        # oppure usare un contatore.
        content_length = request.content_length if request.content_length else 0
        # Apriamo lo stream in lettura
        def generate_chunks(file_stream, size):
            while True:
                data = file_stream.read(size)
                if not data:
                    break
                yield data

        for chunk in generate_chunks(request.stream, chunk_size):
            # Carichiamo la parte su S3
            part_upload = s3_client.upload_part(
                Bucket=S3_BUCKET_NAME,
                Key=f'upload_{upload_uuid}',
                PartNumber=part_number,
                UploadId=upload_id,
                Body=io.BytesIO(chunk)
            )
            parts.append({
                'PartNumber': part_number,
                'ETag': part_upload['ETag']
            })

            total_bytes_uploaded += len(chunk)
            part_number += 1

            # Calcolo percentuale approssimativa
            percentage = 0
            if content_length > 0:
                percentage = int(math.floor((total_bytes_uploaded / content_length) * 100))
                if percentage > 100:
                    percentage = 100

            # Aggiorna DB con la nuova percentuale
            update_stmt = """
                UPDATE s3_progress 
                SET progress = %s
                WHERE upload_uuid = %s
            """
            cursor.execute(update_stmt, (percentage, upload_uuid))
            cnx.commit()

        # Una volta terminati i chunk, concludiamo la multi-part upload
        complete_response = s3_client.complete_multipart_upload(
            Bucket=S3_BUCKET_NAME,
            Key=f'upload_{upload_uuid}',
            UploadId=upload_id,
            MultipartUpload={'Parts': parts}
        )

        # Aggiorna DB: COMPLETED, progress = 100, e salva la URL finale su s3_file_url
        file_url = f"https://{S3_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/upload_{upload_uuid}"
        update_completed_stmt = """
            UPDATE s3_progress 
            SET prg_status = 'COMPLETED', progress = 100, s3_file_url = %s
            WHERE upload_uuid = %s
        """
        cursor.execute(update_completed_stmt, (file_url, upload_uuid))
        cnx.commit()

    except Exception as e:
        # Se qualcosa va storto, settiamo lo stato = ERROR
        error_msg = str(e)
        update_error_stmt = """
            UPDATE s3_progress
            SET prg_status = 'ERROR', err_code = 1, err_msg = %s
            WHERE upload_uuid = %s
        """
        cursor.execute(update_error_stmt, (error_msg, upload_uuid))
        cnx.commit()
    finally:
        cursor.close()
        cnx.close()

    # Ritorniamo l'UUID (anche se in caso di errore, l'utente saprà di dover riprovare)
    return jsonify({"upload_uuid": upload_uuid})


@app.route('/api/s3progress', methods=['GET'])
def api_s3progress():
    """
    Restituisce lo stato di avanzamento (e altri dati) di un upload
    cercando per upload_uuid nella tabella s3_progress.
    """
    upload_uuid = request.args.get('uuid', None)
    if not upload_uuid:
        return jsonify({"error": "Missing uuid parameter"}), 400

    cnx = get_db_connection()
    cursor = cnx.cursor(dictionary=True)
    select_stmt = """
        SELECT upload_uuid, prg_status, err_code, err_msg, progress, s3_file_url
        FROM s3_progress
        WHERE upload_uuid = %s
        LIMIT 1
    """
    cursor.execute(select_stmt, (upload_uuid,))
    row = cursor.fetchone()
    cursor.close()
    cnx.close()

    if not row:
        return jsonify({"error": "Upload UUID not found"}), 404

    return jsonify(row)

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

def get_db_connection():
    """Restituisce una connessione MySQL basata sulle credenziali lette da JSON."""
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

def save_log(text: str):

    def rome_datetime():
        fuso_orario_roma = pytz.timezone('Europe/Rome')
        data_ora_roma = datetime.now(fuso_orario_roma)
        return data_ora_roma.strftime('%Y-%m-%d %H:%M:%S')

    text = f"[{rome_datetime()}] {text}\n"
    with open(LOCAL_FOLDER_PATH + 'log.txt', 'a', encoding='utf-8') as file:
        file.write(text)
