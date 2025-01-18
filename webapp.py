from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import logging
import os
import requests
from urllib.parse import urlparse
import io
import json
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from googleapiclient.http import MediaIoBaseUpload
from google.auth.transport.requests import Request as ytr

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

##################################################################################
# YOUTUBE ->
##################################################################################

# Configurazione YT OAuth 2.0
YT_CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, 'yt_client_secrets.json')
YT_SCOPES = ['https://www.googleapis.com/auth/youtube.upload', 'https://www.googleapis.com/auth/youtube.readonly']

# Creazione cartella upload se non esiste
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def yt_get_oauth_flow():
    return Flow.from_client_secrets_file(
        YT_CLIENT_SECRETS_FILE,
        scopes=YT_SCOPES,
        redirect_uri=url_for('yt_oauth2callback', _external=True)
    )

@app.route('/ytpub')
@app.route('/ytpub/')
def ytpub():
    if 'credentials' not in session:
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
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    except Exception as e:
        session.pop('credentials', None)
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
        credentials = Credentials(**session['credentials'])

        logger.info(f"[300] token = {credentials.token};  refresh_token = {credentials.refresh_token}; session = {session['credentials']}") # DEBUG
        
        revoke = requests.post(
            'https://oauth2.googleapis.com/revoke',
            params={'token': credentials.token},
            headers={'content-type': 'application/x-www-form-urlencoded'}
        )
        
        status_code = getattr(revoke, 'status_code', 500)
        
        # Rimuovi le credenziali dalla sessione indipendentemente dal risultato
        session.pop('credentials', None)
        
#        if status_code == 200:
        return redirect(url_for('ytpub'))
#        else:
#            logger.error(f"Errore nella revoca del token: {revoke.text}")
#            return f'Errore nella revoca del token: {revoke.text}', status_code
            
    except Exception as e:
        session.pop('credentials', None)
        logger.error(f"Errore durante la revoca: {str(e)}")
        return f'Errore durante la revoca: {str(e)}', 500

@app.route('/ytupload/chunk', methods=['POST'])
def yt_upload_chunk():
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
#        logger.info(f"Chunk {chunk_number}/{total_chunks} salvato: {chunk_filename}")        
        
        # Se questo è l'ultimo chunk, salviamo i metadati
        if int(chunk_number) == int(total_chunks) - 1:
            yt_save_metadata(upload_id, request.form)
            return jsonify({
                'success': True,
                'message': 'Upload completato',
                'redirect': url_for('yt_process_upload', upload_id=upload_id, state='init_complete')
            })
            
        return jsonify({'success': True, 'message': 'Chunk ricevuto'})
        
    except Exception as e:
        logger.error(f"Errore nell'upload del chunk: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

    if 'credentials' not in session:
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
