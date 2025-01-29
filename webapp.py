from flask import Flask, Response, render_template, request, redirect, url_for, session, jsonify
import logging
import os
import requests
from urllib.parse import urlparse
import io
import json
import time
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from googleapiclient.http import MediaIoBaseUpload
from google.auth.transport.requests import Request as ytr
from facebook import GraphAPI
from instagram_private_api import Client, ClientCompatPatch

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()  # Generazione automatica di una chiave segreta sicura

# Configurazione per gestire file di grandi dimensioni
CHUNK_SIZE = 5 * 1024 * 1024  # 5MB in bytes
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 * 1024  # 5GB
app.config['REQUEST_CHUNK_SIZE'] = CHUNK_SIZE

# Configurazione dei path assoluti e delle cartelle
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'temp_uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Configurazione del logging
LOG_FILE = os.path.join(BASE_DIR, 'webapp.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def json_sfile_to_obj(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        raise Exception(f"Errore leggendo il file JSON {file_path}: file non trovato")
    except json.JSONDecodeError:
        raise Exception(f"Errore nella decodifica del JSON leggendo il file {file_path}")
    except Exception as e:
        raise Exception(f"Errore leggendo il file JSON {file_path}: {e}")     
    
@app.route('/')
def home():
    return render_template('home.html')
    
@app.route('/robots.txt')
@app.route('/robots.txt/')
def robots():
    return Response("User-agent: *\nDisallow: /\n", mimetype='text/plain')

##################################################################################
# INSTAGRAM ->
##################################################################################

# Instagram API Configuration
INSTAGRAM_APP_ID = 'your_app_id'
INSTAGRAM_APP_SECRET = 'your_app_secret'
INSTAGRAM_REDIRECT_URI = 'http://localhost:5000/instagram_callback'

@app.route('/igpub')
@app.route('/igpub/')
def igpub():
    if 'instagram_access_token' not in session:
        return render_template('igpub-login.html')
    return render_template('igpub-upload.html')

@app.route('/igauth')
def ig_auth():
    auth_url = f"https://api.instagram.com/oauth/authorize?client_id={INSTAGRAM_APP_ID}&redirect_uri={INSTAGRAM_REDIRECT_URI}&scope=user_profile,user_media&response_type=code"
    return redirect(auth_url)

@app.route('/igoauth2callback')
def ig_oauth2callback():
    code = request.args.get('code')
    if not code:
        return 'Authorization failed', 400

    try:
        # Exchange code for access token
        token_url = 'https://api.instagram.com/oauth/access_token'
        response = requests.post(token_url, data={
            'client_id': INSTAGRAM_APP_ID,
            'client_secret': INSTAGRAM_APP_SECRET,
            'grant_type': 'authorization_code',
            'redirect_uri': INSTAGRAM_REDIRECT_URI,
            'code': code
        })
        
        data = response.json()
        session['instagram_access_token'] = data['access_token']
        session['instagram_user_id'] = data['user_id']
        
        return redirect(url_for('igpub'))
        
    except Exception as e:
        logger.error(f"Error during Instagram authentication: {str(e)}")
        return redirect(url_for('igpub'))

@app.route('/iglogout')
def ig_logout():
    session.pop('instagram_access_token', None)
    session.pop('instagram_user_id', None)
    return redirect(url_for('igpub'))

@app.route('/igupload/chunk', methods=['POST'])
def ig_upload_chunk():
    try:
        chunk = request.files.get('chunk')
        chunk_number = request.form.get('chunk_number')
        total_chunks = request.form.get('total_chunks')
        upload_id = request.form.get('upload_id')
        original_filename = request.form.get('original_filename')
        
        if not all([chunk, chunk_number, total_chunks, upload_id, original_filename]):
            return jsonify({'error': 'Missing parameters'}), 400
            
        extension = os.path.splitext(original_filename)[1]
        chunk_filename = f"{upload_id}_{chunk_number}{extension}"
        chunk_path = os.path.join(UPLOAD_FOLDER, chunk_filename)
        
        chunk.save(chunk_path)
        
        if int(chunk_number) == int(total_chunks) - 1:
            ig_save_metadata(upload_id, request.form)
            return jsonify({
                'success': True,
                'message': 'Upload completed',
                'redirect': url_for('ig_process_upload', upload_id=upload_id, state='init_complete')
            })
            
        return jsonify({'success': True, 'message': 'Chunk received'})
        
    except Exception as e:
        logger.error(f"Error in chunk upload: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/igprocess/<upload_id>')
def ig_process_upload(upload_id):
    if 'instagram_access_token' not in session:
        return redirect(url_for('igpub'))

    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        remove_chunks(upload_id)
        return render_template('igpub-process.html', 
                             error=error,
                             upload_id=upload_id)
    
    if state == 'init_complete':
        try:
            # Initialize Instagram API client
            api = Client(
                auto_patch=True,
                authenticate=False,
                access_token=session['instagram_access_token']
            )

            # Get metadata for the upload
            metadata_key = f'metadata_{upload_id}'
            if metadata_key not in session:
                raise Exception("Metadata not found for this upload")
                
            metadata = session[metadata_key]
            
            # Create a chunked file reader
            chunk_file = ChunkedFile(upload_id)
            
            # Upload video to Instagram
            media = api.video_upload(
                chunk_file,
                caption=metadata['caption'],
                title=metadata['title']
            )
            
            # Clean up
            remove_chunks(upload_id)
            session.pop(metadata_key, None)
            
            return redirect(url_for('ig_process_upload',
                                  upload_id=upload_id,
                                  state='complete',
                                  media_id=media['id']))
                                  
        except Exception as e:
            logger.error(f"Error during Instagram upload: {e}")
            remove_chunks(upload_id)
            return redirect(url_for('ig_process_upload',
                                  upload_id=upload_id,
                                  error=str(e)))
    
    elif state == 'complete':
        media_id = request.args.get('media_id')
        return render_template('igpub-process.html',
                             state='complete',
                             media_id=media_id)
    
    return render_template('igpub-process.html',
                         state=state,
                         upload_id=upload_id)

def ig_save_metadata(upload_id, metadata):
    session[f'metadata_{upload_id}'] = {
        'title': metadata.get('title'),
        'caption': metadata.get('caption'),
    }

##################################################################################
# <- INSTAGRAM
##################################################################################


##################################################################################
# TIKTOK ->
##################################################################################

# Configurazione TikTok
TIK_CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, 'tik_client_secrets.json')
tik_credentials = json_sfile_to_obj(TIK_CLIENT_SECRETS_FILE)
TIKTOK_CLIENT_KEY = tik_credentials['client_key']
TIKTOK_CLIENT_SECRET = tik_credentials['client_secret']
TIKTOK_AUTH_URL = 'https://www.tiktok.com/v2/auth/authorize/'
TIKTOK_TOKEN_URL = 'https://open.tiktokapis.com/v2/oauth/token/'
TIKTOK_REFRESH_URL = 'https://open.tiktokapis.com/v2/oauth/token/'
TIKTOK_UPLOAD_URL = 'https://open.tiktokapis.com/v2/post/publish/inbox/video/init/'
TIKTOK_QUERY_CREATOR_URL = 'https://open.tiktokapis.com/v2/post/publish/creator_info/query/'
TIKTOK_PUBLISH_URL = 'https://open.tiktokapis.com/v2/post/publish/video/init/'

@app.route('/tikpub')
@app.route('/tikpub/')
def tikpub():
    if 'tiktok_access_token' not in session:
        return render_template('tikpub-login.html')
    return render_template('tikpub-upload.html')

@app.route('/tikauthorize')
def tik_authorize():
    csrf_state = os.urandom(16).hex()
    session['csrf_state'] = csrf_state
    
    auth_params = {
        'client_key': TIKTOK_CLIENT_KEY,
        'response_type': 'code',
        'scope': 'user.info.basic,video.publish,video.upload',
        'redirect_uri': url_for('tik_oauth2callback', _external=True),
        'state': csrf_state
    }
    
    authorization_url = f"{TIKTOK_AUTH_URL}?{'&'.join(f'{k}={v}' for k, v in auth_params.items())}"
    return redirect(authorization_url)

@app.route('/tikoauth2callback')
@app.route('/tikoauth2callback/')
def tik_oauth2callback():
    try:

        logger.info(f"tikoauth2callback loaded whit params: {request.args}")    # DEBUG

        if request.args.get('state') != session.get('csrf_state'):
            raise ValueError("CSRF state mismatch")
            
        code = request.args.get('code')
        if not code:
            raise ValueError("No authorization code received")
            
        # Exchange code for access token
        token_data = {
            'client_key': TIKTOK_CLIENT_KEY,
            'client_secret': TIKTOK_CLIENT_SECRET,
            'redirect_uri': url_for('tik_oauth2callback', _external=True),
            'code': code,
            'grant_type': 'authorization_code'
        }
        
        response = requests.post(TIKTOK_TOKEN_URL, data=token_data)
        token_info = response.json()
        
        if 'access_token' not in token_info:
            raise ValueError("Failed to obtain access token")
            
        session['tiktok_access_token'] = token_info['access_token']
        session['tiktok_refresh_token'] = token_info.get('refresh_token')
        session['tiktok_token_expires'] = time.time() + token_info.get('expires_in', 86400)
        
    except Exception as e:
        logger.error(f"Error during TikTok authentication: {e}")
        session.pop('tiktok_access_token', None)
        session.pop('tiktok_refresh_token', None)
        session.pop('tiktok_token_expires', None)
        
    return redirect(url_for('tikpub'))

@app.route('/tiklogout')
def tik_logout():
    session.pop('tiktok_access_token', None)
    session.pop('tiktok_refresh_token', None)
    session.pop('tiktok_token_expires', None)
    return redirect(url_for('tikpub'))

@app.route('/tikupload/chunk', methods=['POST'])
def tik_upload_chunk():
    return upload_chunk(tik_save_metadata, 'tik_process_upload')

def upload_video_to_tiktok(
    access_token: str,
    upload_id: str,
    client_key: str,
    video_folder: str = "temp_uploads",
    description: str = "Il mio video su TikTok"
):
    """
    Carica e pubblica un video su TikTok usando l'upload a chunk.
    
    :param access_token:    Token di accesso con permessi validi per caricare video.
    :param open_id:         Identificatore utente (fornito da TikTok dopo l'autenticazione).
    :param client_key:      Client key (app key) dell'app registrata su TikTok Developers.
    :param video_folder:    Cartella che contiene i chunk del video (video_1.mp4, video_2.mp4, ecc.).
    :param description:     Descrizione/testo del video da pubblicare.

    :return:                Dizionario con dati di risposta dalla pubblicazione, oppure eccezione se fallisce.
    """
    
    # Endpoint base per la chiamata (varia a seconda dell'API e della versione!)
    # Qui usiamo un endpoint "ipotetico" derivato da TikTok Open API / Video Upload
    BASE_URL = "https://open-api.tiktok.com"
    
    # 1) Leggi tutti i chunk disponibili nella cartella video_folder, ordinandoli per numero
    #    Assumiamo che i file abbiano la forma video_1.mp4, video_2.mp4, ...
    chunk_files = []
    for filename in os.listdir(video_folder):
        if filename.startswith(upload_id) and filename.endswith(".mp4"):
            # Estrai il numero dopo "video_" e prima di ".mp4"
            # Esempio: "video_12.mp4" -> 12
            try:
                part_number = int(filename.replace(f"{upload_id}_", "").replace(".mp4", ""))
                chunk_files.append((part_number, os.path.join(video_folder, filename)))
            except ValueError:
                # Se non riesce a convertire in int, ignora il file
                pass
    
    # Ordina i file in base al numero del chunk
    chunk_files.sort(key=lambda x: x[0])
    
    # Se non ci sono file, interrompi
    if not chunk_files:
        raise ValueError(f"Nessun file chunk trovato nella cartella {video_folder}.")
    
    # Calcola dimensione totale del video sommando la dimensione di ogni chunk
    total_size = 0
    for _, path in chunk_files:
        total_size += os.path.getsize(path)
    
    # 2) Inizializza la sessione di upload (INIT)
    #    L'API di init potrebbe richiedere parametri aggiuntivi come la dimensione totale del file, il MD5, ecc.
    #    Il seguente payload e endpoint sono a scopo illustrativo; controlla la doc ufficiale per i campi corretti.
    init_url = f"{BASE_URL}/video/upload/init/"
    init_payload = {
        "access_token": access_token,
        "client_key": client_key,
        "video_size": total_size,
        # eventuali altri campi richiesti da TikTok
    }
    
    init_response = requests.post(init_url, json=init_payload, timeout=60)
    init_data = init_response.json()
    
    if init_response.status_code != 200 or "data" not in init_data:
        raise RuntimeError(f"Errore durante INIT: {init_response.text}")
    
    upload_id = init_data["data"].get("upload_id")
    if not upload_id:
        raise RuntimeError("Impossibile ottenere upload_id dalla risposta INIT.")
    
    # 3) Caricamento chunk per chunk (UPLOAD PART)
    part_url = f"{BASE_URL}/video/upload/part/"
    
    for index, (part_number, chunk_path) in enumerate(chunk_files, start=1):
        with open(chunk_path, "rb") as f:
            chunk_data = f.read()
        
        part_payload = {
            "access_token": access_token,
#            "open_id": open_id,
            "client_key": client_key,
            "upload_id": upload_id,
            "part_number": index,   # Indice sequenziale richiesto dall'API
        }
        
        # Alcune API accettano i chunk come multipart/form-data
        # others come raw data con un header specifico. Qui mostriamo multipart:
        files = {
            "video_chunk": (f"chunk_{index}.mp4", chunk_data, "video/mp4")
        }
        
        part_response = requests.post(part_url, data=part_payload, files=files, timeout=120)
        part_data = part_response.json()
        
        if part_response.status_code != 200 or not part_data.get("data", {}).get("is_success"):
            raise RuntimeError(f"Errore durante UPLOAD PART {index}: {part_response.text}")
        
        print(f"Caricato chunk n°{index} ({chunk_path}) con successo.")
    
    # 4) Completa l'upload (COMPLETE)
    complete_url = f"{BASE_URL}/video/upload/complete/"
    complete_payload = {
        "access_token": access_token,
#        "open_id": open_id,
        "client_key": client_key,
        "upload_id": upload_id,
    }
    
    complete_response = requests.post(complete_url, json=complete_payload, timeout=60)
    complete_data = complete_response.json()
    
    if complete_response.status_code != 200 or not complete_data.get("data", {}).get("is_success"):
        raise RuntimeError(f"Errore durante COMPLETE: {complete_response.text}")
    
    # 5) Pubblica il video (PUBLISH)
    publish_url = f"{BASE_URL}/video/publish/"
    publish_payload = {
        "access_token": access_token,
#        "open_id": open_id,
        "client_key": client_key,
        "upload_id": upload_id,
        "text": description  # La descrizione del video
    }
    
    publish_response = requests.post(publish_url, json=publish_payload, timeout=60)
    publish_data = publish_response.json()
    
    if publish_response.status_code != 200 or not publish_data.get("data", {}).get("video_id"):
        raise RuntimeError(f"Errore durante PUBLISH: {publish_response.text}")
    
    video_id = publish_data["data"].get("video_id")
    print(f"Video pubblicato con successo! Video ID: {video_id}")
    
    return publish_data

@app.route('/tikprocess/<upload_id>')
def tik_process_upload(upload_id):

    logger.info("[100]")  #DEBUG

    if 'tiktok_access_token' not in session:
        return redirect(url_for('tikpub'))

    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        remove_chunks(upload_id)
        return render_template('tikpub-process.html', 
                             error=error,
                             upload_id=upload_id)
    
    if state == 'init_complete':

        logger.info("[200]")  #DEBUG

        try:
            # Ensure token is fresh
            tik_refresh_credentials()
            
            # Get metadata
            metadata_key = f'metadata_{upload_id}'
            if metadata_key not in session:
                raise Exception("Metadata not found for this upload")
                
            metadata = session[metadata_key]
            
            # Combine all chunks into a single file
            final_path = os.path.join(UPLOAD_FOLDER, f"final_{upload_id}.mp4")




#            res = upload_video_to_tiktok(session['tiktok_access_token'], upload_id, TIKTOK_CLIENT_KEY, UPLOAD_FOLDER, metadata['description'])
#            remove_chunks(upload_id)
#            session.pop(metadata_key, None)            
#            return redirect(url_for('tik_process_upload', upload_id=upload_id, state='complete'))



            combine_chunks(upload_id, final_path)
            total_size = os.path.getsize(final_path)

            logger.info("[300]")  #DEBUG

            
            with open(final_path, 'rb') as video_file:

                logger.info(f"[400] metadata = {metadata}")  #DEBUG


                # First, request an upload URL
                headers = {
                    'Authorization': f"Bearer {session['tiktok_access_token']}",
                    'Content-Type': "application/json; charset=UTF-8",
                }
                
                params = {
                    "post_info": {
                        'privacy_level': metadata['privacy'],
                        'title': metadata['description']
                    }, 
                    "source_info": {
                        'source': 'FILE_UPLOAD',
                        'video_size': total_size,
                        'chunk_size': total_size,
                        'total_chunk_count': 1
                    }
                }

                logger.info(f"[500] params = {params}")  #DEBUG

                
                upload_url_response = requests.post(
                    TIKTOK_UPLOAD_URL,
                    headers=headers,
                    json=params
                ).json()

                logger.info("[600]")  #DEBUG


                logger.info(f"upload_url_response: {upload_url_response}")  #DEBUG
                
                if ('data' not in upload_url_response) or ('upload_url' not in upload_url_response.get('data')):
                    error_code = upload_url_response.get('error')['code']
                    error_msg = upload_url_response.get('error')['message']
                    if error_code != 'ok':
                        raise Exception(f'[{error_code}] Failed to get upload URL from TikTok cause "{error_msg}"')
                    else:
                        raise Exception("Failed to get upload URL from TikTok")

                # Then upload the video
                headers = {
                    'Content-Type': "video/mp4",
                    'Content-Range': f"bytes 0-{total_size - 1}/{total_size}",
                    'Content-Length': f"{total_size}"
                }
                
                upload_url = upload_url_response.get('data')['upload_url']
                file_data = video_file.read()
                upload_response = requests.put(
                    upload_url,
                    data=file_data,
                    headers=headers
                )

                logger.info(f"[{upload_response.status_code}] upload_url: {upload_url}; upload_response: {upload_response}")  #DEBUG
                
            # Clean up
            remove_chunks(upload_id)
            os.remove(final_path)
            session.pop(metadata_key, None)
            
            return redirect(url_for('tik_process_upload',
                                  upload_id=upload_id,
                                  state='complete'))
                                  
        except Exception as e:
            logger.error(f"Error during TikTok upload: {e}")
            remove_chunks(upload_id)
            return redirect(url_for('tik_process_upload',
                                  upload_id=upload_id,
                                  error=str(e)))
    
    elif state == 'complete':
        return render_template('tikpub-process.html',
                             state='complete')
    
    return render_template('tikpub-process.html',
                         state=state,
                         upload_id=upload_id)

@app.route('/tiktokabKGNUGYiZ9K9NrN1U6fFiGVJpOy5y04.txt')
def tik_verfile():
    return f"tiktok-developers-site-verification=abKGNUGYiZ9K9NrN1U6fFiGVJpOy5y04"

def tik_refresh_credentials():
    """Refresh TikTok access token if it's close to expiring"""
    if time.time() >= session.get('tiktok_token_expires', 0) - 300:  # 5 minutes buffer
        try:
            refresh_data = {
                'client_key': TIKTOK_CLIENT_KEY,
                'client_secret': TIKTOK_CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'refresh_token': session['tiktok_refresh_token']
            }
            
            response = requests.post(TIKTOK_REFRESH_URL, data=refresh_data)
            token_info = response.json()
            
            if 'access_token' not in token_info:
                raise ValueError("Failed to refresh access token")
                
            session['tiktok_access_token'] = token_info['access_token']
            session['tiktok_refresh_token'] = token_info.get('refresh_token')
            session['tiktok_token_expires'] = time.time() + token_info.get('expires_in', 86400)
            
        except Exception as e:
            logger.error(f"Error refreshing TikTok token: {e}")
            raise

def tik_save_metadata(upload_id, metadata):
    """Salva i metadati del video nella sessione"""
    session[f'metadata_{upload_id}'] = {
        'description': metadata.get('description'),
        'privacy': metadata.get('privacy')
    }

def combine_chunks(upload_id, final_path):
    """Combine all chunks into a single file"""
    with open(final_path, 'wb') as outfile:
        chunk_num = 0
        while True:
            chunk_path = os.path.join(UPLOAD_FOLDER, f"{upload_id}_{chunk_num}.mp4")
            if not os.path.exists(chunk_path):
                break
            with open(chunk_path, 'rb') as chunk_file:
                outfile.write(chunk_file.read())
            chunk_num += 1

##################################################################################
# <- TIKTOK
##################################################################################           

##################################################################################
# YOUTUBE ->
##################################################################################

# Configurazione YT OAuth 2.0
YT_CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, 'yt_client_secrets.json')
YT_SCOPES = ['https://www.googleapis.com/auth/youtube.upload', 'https://www.googleapis.com/auth/youtube.readonly']

@app.route('/ytpub')
@app.route('/ytpub/')
def ytpub():
    if 'YTCredentials' not in session:
        return render_template('ytpub-login.html')
    youtube = yt_refresh_credentials()
    return render_template('ytpub-upload.html', categories=yt_categories(youtube))

@app.route('/ytauthorize')
def yt_authorize():
    flow = yt_get_oauth_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/ytoauth2callback')
def yt_oauth2callback():
    try:
        flow = yt_get_oauth_flow()
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        session['YTCredentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    except Exception as e:
        session.pop('YTCredentials', None)
        logger.error(f"Errore durante la connessione a YouTube: {e}")
    return redirect(url_for('ytpub'))           

@app.route('/ytlogout')
def yt_logout():
    """
    Revoca l'accesso e cancella le credenziali dalla sessione.
    """
    if 'credentials' not in session:
        logger.error(f"Nessuna credenziale da revocare.")
        return redirect(url_for('ytpub'))

    try:
        yt_refresh_credentials()    
        credentials = Credentials(**session['YTCredentials'])

        logger.info(f"[300] token = {credentials.token};  refresh_token = {credentials.refresh_token}; session = {session['YTCredentials']}") # DEBUG
        
        revoke = requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': credentials.token},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )
        
        status_code = getattr(revoke, 'status_code', 500)
        
        # Rimuovi le credenziali dalla sessione indipendentemente dal risultato
        session.pop('YTCredentials', None)
        
        return redirect(url_for('ytpub'))
            
    except Exception as e:
        session.pop('YTCredentials', None)
        logger.error(f"Errore durante la revoca: {str(e)}")
        return f'Errore durante la revoca: {str(e)}', 500

@app.route('/ytupload/chunk', methods=['POST'])
def yt_upload_chunk():
    return upload_chunk(yt_save_metadata, 'yt_process_upload')

@app.route('/ytupload/url', methods=['POST'])
def yt_upload_url():
    """Gestisce l'upload di un video tramite URL"""
    try:
        video_url = request.form.get('video_url')
        upload_id = request.form.get('upload_id')
        
        if not all([video_url, upload_id]):
            return jsonify({'error': 'URL video e upload_id richiesti'}), 400
            
        # Determina l'estensione dal URL
        extension = os.path.splitext(urlparse(video_url).path)[1]
        if not extension:
            extension = '.mp4'  # Estensione di default se non rilevata
            
        temp_path = os.path.join(UPLOAD_FOLDER, f"{upload_id}_0{extension}")
        
        if not download_and_chunk_file(video_url, upload_id):
            return jsonify({'error': 'Errore durante il download del video'}), 500
            
        yt_save_metadata(upload_id, request.form)
        
        return jsonify({
            'success': True,
            'message': 'Video scaricato con successo',
            'redirect': url_for('yt_process_upload', upload_id=upload_id, state='init_complete')
        })
        
    except Exception as e:
        logger.error(f"Errore nell'upload da URL: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ytupload/thumbnail', methods=['POST'])
def yt_upload_thumbnail():
    """Gestisce l'upload della thumbnail"""
    try:
        upload_id = request.form.get('upload_id')
        if not upload_id:
            return jsonify({'error': 'upload_id richiesto'}), 400
            
        if 'thumbnail' in request.files:
            if yt_handle_thumbnail_upload(upload_id, request.files['thumbnail']):
                return jsonify({'success': True, 'message': 'Thumbnail caricata con successo'})
            return jsonify({'error': 'Errore durante il salvataggio della thumbnail'}), 500
            
        elif 'thumbnail_url' in request.form:
            thumb_url = request.form.get('thumbnail_url')
            extension = os.path.splitext(urlparse(thumb_url).path)[1]
            if not extension:
                extension = '.jpg'  # Estensione di default per thumbnail
                
            thumb_path = os.path.join(UPLOAD_FOLDER, f"thumb_{upload_id}{extension}")
            
            if download_file(thumb_url, thumb_path):
                return jsonify({'success': True, 'message': 'Thumbnail scaricata con successo'})
            return jsonify({'error': 'Errore durante il download della thumbnail'}), 500
            
        return jsonify({'error': 'Nessuna thumbnail fornita'}), 400
        
    except Exception as e:
        logger.error(f"Errore nell'upload della thumbnail: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ytprocess/<upload_id>')
def yt_process_upload(upload_id):

    if 'YTCredentials' not in session:
        return redirect(url_for('ytpub'))

    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        remove_chunks(upload_id)
        return render_template('ytpub-process.html', 
                             error=error,
                             upload_id=upload_id)
    
    if state == 'init_complete':
        try:
            youtube = yt_refresh_credentials()
            
            # Preparazione dei metadati
            metadata_key = f'metadata_{upload_id}'
            if metadata_key not in session:
                raise Exception("Metadati non trovati per questo upload")
                
            metadata = session[metadata_key]
            body = {
                'snippet': {
                    'title': metadata['title'],
                    'description': metadata['description'],
                    'tags': metadata['tags'],
                    'categoryId': metadata['category'],  
                    'defaultAudioLanguage': 'it'
                },
                'status': {
                    'privacyStatus': metadata['privacy'],
                    'selfDeclaredMadeForKids': False
                }
            }
            
            # Rimuoviamo i metadati dalla sessione dopo averli utilizzati
            session.pop(metadata_key, None)            

            # Crea un oggetto file-like che legge i chunk
            chunk_file = ChunkedFile(upload_id)

            # Prepara l'upload media utilizzando l'oggetto file personalizzato
            media = MediaIoBaseUpload(
                chunk_file,
                mimetype='video/*',
                resumable=True,
                chunksize=-1    # Usa la dimensione di chunk predefinita
            )

            # Prepara la richiesta di inserimento video su YouTube
            ytrequest = youtube.videos().insert(
                part="snippet,status",
                body=body,
                media_body=media
            )

            # Esegue l'upload in modalità resumable, monitorando il progresso
            response = None
            while response is None:
                status, response = ytrequest.next_chunk()
                if status:
                    logger.info(f"Upload progress: {int(status.progress() * 100)}%")
            
            video_id = response['id']
            
            # Upload della thumbnail se presente
            thumb_file = next((
                f for f in os.listdir(UPLOAD_FOLDER) 
                if f.startswith(f"thumb_{upload_id}")
            ), None)
            
            if thumb_file:
                thumb_path = os.path.join(UPLOAD_FOLDER, thumb_file)
                youtube.thumbnails().set(
                    videoId=video_id,
                    media_body=MediaFileUpload(thumb_path)
                ).execute()
            
            return redirect(url_for('yt_process_upload',
                                  upload_id=upload_id,
                                  state='complete',
                                  video_id=video_id))
                                  
        except Exception as e:
            logger.error(f"Errore durante l'upload su YouTube: {e}")
            remove_chunks(upload_id)
            return redirect(url_for('yt_process_upload',
                                  upload_id=upload_id,
                                  error=str(e)))
    
    elif state == 'complete':
        video_id = request.args.get('video_id')
        
        # Pulizia dei file temporanei
        remove_chunks(upload_id)
        
        # Pulizia dei metadati dalla sessione se non sono stati già rimossi
        session.pop(f'metadata_{upload_id}', None)
        
        return render_template('ytpub-process.html',
                             state='complete',
                             video_id=video_id)
    
    return render_template('ytpub-process.html',
                         state=state,
                         upload_id=upload_id)

def yt_get_oauth_flow():
    return Flow.from_client_secrets_file(
        YT_CLIENT_SECRETS_FILE,
        scopes=YT_SCOPES,
        redirect_uri=url_for('yt_oauth2callback', _external=True)
    )

def yt_categories(youtube):
    """
    Recupera la lista delle categorie video disponibili da YouTube.
    
    Args:
        youtube: Il servizio YouTube autenticato
        
    Returns:
        list: Lista di dizionari con id e titolo delle categorie
    """
    try:
        # Recupera le categorie per la regione 'US' (potrebbe essere modificato per altre regioni)
        categories_response = youtube.videoCategories().list(
            part='snippet',
            regionCode='IT',
            hl='it_IT'
        ).execute()
        
        # Estrai e formatta le categorie
        categories = []
        for category in categories_response['items']:
            # Alcune categorie potrebbero essere deprecate o non disponibili per l'upload
            if (not int(category['id']) in [25, 22]) and category['snippet']['assignable']:
                categories.append({
                    'id': category['id'],
                    'title': category['snippet']['title']
                })
        
        # Ordina le categorie per titolo
        categories = sorted(categories, key=lambda x: x['title'])
        categories.insert(0, {'id': '22', 'title': 'Persone e blog'})
        categories.insert(0, {'id': '25', 'title': 'Notizie e politica'})
        return categories
        
    except Exception as e:
        logger.error(f"Errore nel recupero delle categorie: {e}")
        # Ritorna una lista predefinita di categorie comuni in caso di errore
        return [
            {'id': '25', 'title': 'Notizie e politica'},
            {'id': '22', 'title': 'Persone e blog'},
            {'id': '1', 'title': 'Film & Animation'},
            {'id': '2', 'title': 'Autos & Vehicles'},
            {'id': '10', 'title': 'Music'},
            {'id': '15', 'title': 'Pets & Animals'},
            {'id': '17', 'title': 'Sports'},
            {'id': '19', 'title': 'Travel & Events'},
            {'id': '20', 'title': 'Gaming'},
            {'id': '23', 'title': 'Comedy'},
            {'id': '24', 'title': 'Intrattenimento'},
            {'id': '26', 'title': 'Howto & Style'},
            {'id': '27', 'title': 'Education'},
            {'id': '28', 'title': 'Science & Technology'},
            {'id': '29', 'title': 'Nonprofits & Activism'}
        ] 

def yt_handle_thumbnail_upload(upload_id, thumb_file):
    """Gestisce il salvataggio della thumbnail"""
    try:
        if thumb_file:
            extension = os.path.splitext(thumb_file.filename)[1]
            thumb_path = os.path.join(UPLOAD_FOLDER, f"thumb_{upload_id}{extension}")
            thumb_file.save(thumb_path)
            return True
    except Exception as e:
        logger.error(f"Errore durante il salvataggio della thumbnail: {str(e)}")
        return False

def yt_save_metadata(upload_id, metadata):
    """Salva i metadati del video nella sessione"""
    session[f'metadata_{upload_id}'] = {
        'title': metadata.get('title'),
        'description': metadata.get('description'),
        'tags': metadata.get('tags', '').split(',') if metadata.get('tags') else None,
        'category': metadata.get('category'),
        'privacy': metadata.get('privacy')
    }

def yt_refresh_credentials():    
    # Controllo e rinnovo delle credenziali se necessario
    if 'YTCredentials' not in session:
        logger.error("Credenziali mancati nella sessione")
        raise Exception("Credenziali mancati nella sessione")
    credentials = Credentials(**session['YTCredentials'])
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(ytr())
            session['YTCredentials'] = {
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': credentials.scopes
            }
        except Exception as e:
            logger.error(f"Errore nel rinnovo delle credenziali: {e}")
            session.pop('YTCredentials', None)
            return redirect(url_for('ytpub'))
    return build('youtube', 'v3', credentials=credentials, cache_discovery=False)  

##################################################################################
# <- YOUTUBE
##################################################################################

def download_and_chunk_file(url, upload_id):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        filename = os.path.basename(urlparse(url).path)
        extension = os.path.splitext(filename)[1]
        chunk_number = 0
        
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            chunk_filename = f"{upload_id}_{chunk_number}{extension}"
            chunk_path = os.path.join(UPLOAD_FOLDER, chunk_filename)
            
            with open(chunk_path, 'wb') as f:
                f.write(chunk)
            chunk_number += 1
        return True
    except Exception as e:
        logger.error(f"Errore durante il download del file: {str(e)}")
        return False

def download_file(url, temp_path):
    """Scarica un file da un URL"""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(temp_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        return True
    except Exception as e:
        logger.error(f"Errore durante il download del file: {str(e)}")
        return False

def remove_chunks(upload_id):
    # Pulizia dei file temporanei
    for filename in os.listdir(UPLOAD_FOLDER):
        if filename.startswith(upload_id) or filename.startswith(f"thumb_{upload_id}"):
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, filename))
            except Exception as e:
                logger.error(f"Errore durante la rimozione del file {filename}: {str(e)}")  

def upload_chunk(save_metadata_callback, redir_func_name):
    """
    Gestisce l'upload di un singolo chunk del file.
    Ogni chunk viene salvato come file temporaneo separato.
    """
    try:
        chunk = request.files.get('chunk')
        chunk_number = request.form.get('chunk_number')
        total_chunks = request.form.get('total_chunks')
        upload_id = request.form.get('upload_id')
        original_filename = request.form.get('original_filename')
        
        if not all([chunk, chunk_number, total_chunks, upload_id, original_filename]):
            return jsonify({'error': 'Parametri mancanti'}), 400
            
        extension = os.path.splitext(original_filename)[1]
        chunk_filename = f"{upload_id}_{chunk_number}{extension}"
        chunk_path = os.path.join(UPLOAD_FOLDER, chunk_filename)
        
        chunk.save(chunk_path)
       
        # Se questo è l'ultimo chunk, salviamo i metadati
        if int(chunk_number) == int(total_chunks) - 1:
            save_metadata_callback(upload_id, request.form)
            return jsonify({
                'success': True,
                'message': 'Upload completato',
                'redirect': url_for(redir_func_name, upload_id=upload_id, state='init_complete')
            })
            
        return jsonify({'success': True, 'message': 'Chunk ricevuto'})
        
    except Exception as e:
        logger.error(f"Errore nell'upload del chunk: {e}")
        return jsonify({'error': str(e)}), 500
     
class ChunkedFile(io.RawIOBase):
    def __init__(self, upload_id):
        self.base_dir = UPLOAD_FOLDER
        self.upload_id = upload_id
        self.extension = '.mp4'
        self.current_chunk_index = 0   # Indice del chunk corrente
        self.chunk_stream = None
        self.end_of_file = False
        self._pos = 0                  # Posizione corrente nel flusso logico
        self.total_size = 0
        self.chunks = []               # Lista di tuple (filepath, size)

        chunk_name_prefix = f"{self.upload_id}_"
        for nome_file in os.listdir(UPLOAD_FOLDER):
            if nome_file.startswith(chunk_name_prefix):
                # Estrae la parte rimanente dopo il prefisso: {chunk_number}{extension}
                resto = nome_file[len(chunk_name_prefix):]
                # Separa la parte numerica dall'estensione
                numero_str, self.extension = os.path.splitext(resto)


        # Costruisci la lista dei chunk e calcola la dimensione totale
        chunk = 0
        while True:
            path = os.path.join(self.base_dir, f"{self.upload_id}_{chunk}{self.extension}")
            if os.path.exists(path):
                size = os.path.getsize(path)
                self.chunks.append((path, size))
                self.total_size += size
                chunk += 1
            else:
                break

    def _open_chunk(self, index):
        """Apre il chunk specificato dall'indice e lo imposta come corrente."""
        if 0 <= index < len(self.chunks):
            path, _ = self.chunks[index]
            if self.chunk_stream:
                self.chunk_stream.close()
            self.chunk_stream = open(path, 'rb')
            self.current_chunk_index = index
            self.end_of_file = False
        else:
            self.end_of_file = True
            if self.chunk_stream:
                self.chunk_stream.close()
            self.chunk_stream = None

    def _open_next_chunk(self):
        """Passa al chunk successivo rispetto a quello corrente."""
        self._open_chunk(self.current_chunk_index + 1)

    def readinto(self, b):
        """Legge dati nei buffer b dai chunk in sequenza."""
        if self.end_of_file:
            return 0

        # Se non c'è un chunk corrente aperto, aprine uno
        if self.chunk_stream is None:
            self._open_chunk(self.current_chunk_index)
            if self.end_of_file:
                return 0

        total_read = 0
        while total_read < len(b) and not self.end_of_file:
            chunk_read = self.chunk_stream.readinto(memoryview(b)[total_read:])
            if chunk_read == 0:
                # Se il chunk corrente è terminato, passa al successivo
                self._open_next_chunk()
                if self.end_of_file:
                    break
            else:
                total_read += chunk_read

        self._pos += total_read
        return total_read

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        """
        Supporta:
         - seek(0, SEEK_SET): riavvia dall'inizio.
         - seek(offset, SEEK_SET): sposta a una posizione arbitraria se possibile.
         - seek(0, SEEK_CUR): nessun cambiamento, restituisce la posizione corrente.
         - seek(0, SEEK_END): posiziona alla fine del file.
        """
        # Gestione speciale per seek(0, SEEK_CUR)
        if whence == io.SEEK_CUR and offset == 0:
            return self._pos

        if whence == io.SEEK_SET:
            if offset == 0:
                # Riavvia dall'inizio
                self.current_chunk_index = 0
                self._pos = 0
                self.end_of_file = False
                if self.chunk_stream:
                    self.chunk_stream.close()
                    self.chunk_stream = None
                return 0
            elif 0 < offset <= self.total_size:
                # Trova il chunk che contiene la posizione offset
                cumulative = 0
                for idx, (path, size) in enumerate(self.chunks):
                    if cumulative + size > offset:
                        # Questo chunk contiene la posizione richiesta
                        self.current_chunk_index = idx
                        self._open_chunk(idx)
                        # Calcola la posizione all'interno del chunk
                        relative_offset = offset - cumulative
                        self.chunk_stream.seek(relative_offset, io.SEEK_SET)
                        self._pos = offset
                        return self._pos
                    cumulative += size
                # Se l'offset corrisponde esattamente alla fine
                return self.seek(0, io.SEEK_END)
            else:
                raise io.UnsupportedOperation("seek offset fuori dai limiti")
        elif whence == io.SEEK_END and offset == 0:
            # Posiziona alla fine del file
            self._pos = self.total_size
            self.end_of_file = True
            if self.chunk_stream:
                self.chunk_stream.close()
                self.chunk_stream = None
            return self._pos
        else:
            raise io.UnsupportedOperation(f"Seek non supportato per i parametri dati (offset={offset}, whence={whence})")
