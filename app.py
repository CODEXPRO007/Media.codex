#!/usr/bin/env python3
"""
MediaVault Pro — Professional File Hosting with Auth
Run: python app.py
"""
import os, uuid, json, re, io, zipfile, tarfile, hashlib, secrets, socket, mimetypes
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   send_file, jsonify, Response, abort, flash, session, stream_with_context)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'mediavault_pro_2024_changeme_in_production'

BASE_DIR    = os.path.dirname(__file__)
UPLOAD_DIR  = os.path.join(BASE_DIR, 'uploads')
DATA_DIR    = os.path.join(BASE_DIR, 'data')
USERS_FILE  = os.path.join(DATA_DIR, 'users.json')
FILES_FILE  = os.path.join(DATA_DIR, 'files.json')
ACTIVITY_FILE = os.path.join(DATA_DIR, 'activity.json')

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10 GB
DEFAULT_QUOTA = 10 * 1024  # 5 GB in MB

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ─── Data Helpers ────────────────────────────────────────────────────────────

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f: return json.load(f)
    return {}

def save_users(d):
    with open(USERS_FILE, 'w') as f: json.dump(d, f, indent=2, default=str)

def load_files():
    if os.path.exists(FILES_FILE):
        with open(FILES_FILE) as f: return json.load(f)
    return {}

def save_files(d):
    with open(FILES_FILE, 'w') as f: json.dump(d, f, indent=2, default=str)

def load_activity():
    if os.path.exists(ACTIVITY_FILE):
        with open(ACTIVITY_FILE) as f: return json.load(f)
    return []

def save_activity(d):
    with open(ACTIVITY_FILE, 'w') as f: json.dump(d[-500:], f, indent=2, default=str)

def add_activity(uid, action, detail='', fid=None):
    acts = load_activity()
    acts.append({'uid': uid, 'action': action, 'detail': detail, 'fid': fid,
                  'at': datetime.now().timestamp()})
    save_activity(acts)

# ─── Utility ─────────────────────────────────────────────────────────────────

def file_type(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext in ['mp4','avi','mov','mkv','webm','flv','wmv','m4v','3gp','ts']: return 'video'
    if ext in ['mp3','wav','ogg','flac','aac','m4a','wma','opus']: return 'audio'
    if ext in ['jpg','jpeg','png','gif','webp','bmp','svg','ico','tiff','avif']: return 'image'
    if ext in ['zip','rar','7z','tar','gz','bz2','xz','tar.gz','tar.bz2']: return 'archive'
    if ext == 'pdf': return 'pdf'
    if ext in ['doc','docx','xls','xlsx','ppt','pptx','odt']: return 'document'
    if ext in ['py','js','ts','html','css','json','xml','yaml','sh','cpp','c','java','go','rs','php']: return 'code'
    if ext in ['txt','md','csv','log','ini','conf']: return 'text'
    return 'file'

def fmt_size(b):
    b = int(b or 0)
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"

def fmt_date(ts):
    if not ts: return '—'
    return datetime.fromtimestamp(float(ts)).strftime('%d %b %Y, %I:%M %p')

def fmt_rel(ts):
    if not ts: return '—'
    diff = datetime.now() - datetime.fromtimestamp(float(ts))
    s = int(diff.total_seconds())
    if s < 60: return f"{s}s ago"
    if s < 3600: return f"{s//60}m ago"
    if s < 86400: return f"{s//3600}h ago"
    return f"{s//86400}d ago"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return '127.0.0.1'

def md5_file(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''): h.update(chunk)
    return h.hexdigest()

def user_storage_used(uid):
    files = load_files()
    total = sum(
        os.path.getsize(os.path.join(UPLOAD_DIR, f['stored_name']))
        for f in files.values()
        if f.get('owner_id') == uid and os.path.exists(os.path.join(UPLOAD_DIR, f['stored_name']))
    )
    return total

def user_file_count(uid):
    files = load_files()
    return sum(1 for f in files.values() if f.get('owner_id') == uid)

def check_expiry():
    """Delete expired files"""
    files = load_files()
    changed = False
    now = datetime.now().timestamp()
    for fid in list(files.keys()):
        exp = files[fid].get('expires_at')
        if exp and float(exp) < now:
            fp = os.path.join(UPLOAD_DIR, files[fid]['stored_name'])
            if os.path.exists(fp): os.remove(fp)
            del files[fid]
            changed = True
    if changed: save_files(files)

app.jinja_env.globals.update(
    file_type=file_type, fmt_size=fmt_size, fmt_date=fmt_date, fmt_rel=fmt_rel,
    get_local_ip=get_local_ip
)

# ─── Auth Decorators ─────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'info')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        users = load_users()
        if not users.get(session['user_id'], {}).get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' not in session: return None
    return load_users().get(session['user_id'])

app.jinja_env.globals['get_current_user'] = get_current_user

# ─── Context Processor ───────────────────────────────────────────────────────

@app.context_processor
def inject_user():
    user = get_current_user()
    quota_pct = 0
    if user:
        used = user_storage_used(user['id'])
        quota_bytes = user.get('quota_mb', DEFAULT_QUOTA) * 1024 * 1024
        quota_pct = min(100, int(used / quota_bytes * 100)) if quota_bytes else 0
        user['_storage_used'] = used
        user['_quota_bytes'] = quota_bytes
        user['_quota_pct'] = quota_pct
    return dict(current_user=user)

# ═══════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/public')
def public_gallery():
    check_expiry()
    files = load_files()
    users = load_users()
    q = request.args.get('q', '').lower()
    ftype = request.args.get('type', '')
    sort = request.args.get('sort', 'newest')

    result = []
    for fid, info in files.items():
        if not info.get('is_public'): continue
        if info.get('file_password'): continue  # password protected public files hidden from gallery
        fp = os.path.join(UPLOAD_DIR, info['stored_name'])
        if not os.path.exists(fp): continue
        if q and q not in info['original_name'].lower() and q not in info.get('description','').lower(): continue
        if ftype and info.get('type') != ftype: continue
        result.append({**info, 'id': fid, 'owner_name': users.get(info.get('owner_id',''), {}).get('username','?')})

    if sort == 'newest': result.sort(key=lambda x: x.get('uploaded_at', 0), reverse=True)
    elif sort == 'oldest': result.sort(key=lambda x: x.get('uploaded_at', 0))
    elif sort == 'size_desc': result.sort(key=lambda x: x.get('size', 0), reverse=True)
    elif sort == 'popular': result.sort(key=lambda x: x.get('views', 0) + x.get('downloads', 0), reverse=True)

    return render_template('public.html', files=result, q=q, ftype=ftype, sort=sort, total=len(result))

# ═══════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')

        users = load_users()
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters.', 'error'); return render_template('register.html')
        if not re.match(r'^[a-z0-9_]+$', username):
            flash('Username: only letters, numbers, underscore.', 'error'); return render_template('register.html')
        if any(u['username'] == username for u in users.values()):
            flash('Username already taken.', 'error'); return render_template('register.html')
        if not email or '@' not in email:
            flash('Valid email required.', 'error'); return render_template('register.html')
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error'); return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'error'); return render_template('register.html')

        uid = str(uuid.uuid4())[:12]
        is_admin = len(users) == 0  # first user is admin
        users[uid] = {
            'id': uid, 'username': username, 'email': email,
            'password_hash': generate_password_hash(password),
            'created_at': datetime.now().timestamp(),
            'is_admin': is_admin,
            'bio': '', 'quota_mb': DEFAULT_QUOTA,
            'api_token': 'tok_' + secrets.token_hex(20),
            'avatar_color': ['#E8A838','#4A9EFF','#A855F7','#2DD672','#FF6B35','#22D3EE'][len(users) % 6],
            'bandwidth_used': 0,
        }
        save_users(users)
        add_activity(uid, 'register', f'New user: {username}')
        session['user_id'] = uid
        session['username'] = username
        flash(f'Welcome to MediaVault, {username}! 🎉', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip().lower()
        password = request.form.get('password', '')
        users = load_users()
        user = next((u for u in users.values() if u['username'] == login_id or u['email'] == login_id), None)
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password.', 'error')
            return render_template('login.html')
        session['user_id'] = user['id']
        session['username'] = user['username']
        add_activity(user['id'], 'login', 'User logged in')
        flash(f'Welcome back, {user["username"]}!', 'success')
        next_url = request.args.get('next', url_for('index'))
        return redirect(next_url)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ═══════════════════════════════════════════════════════════════
# MAIN FILE ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/')
@login_required
def index():
    check_expiry()
    uid = session['user_id']
    files = load_files()
    q = request.args.get('q', '').lower().strip()
    ftype = request.args.get('type', '')
    folder = request.args.get('folder', '')
    sort = request.args.get('sort', 'newest')
    show_starred = request.args.get('starred', '') == '1'

    result = []
    folders_set = set()
    type_counts = {'video':0,'audio':0,'image':0,'archive':0,'document':0,'code':0,'text':0,'pdf':0,'file':0}
    total_size_raw = 0

    for fid, info in files.items():
        if info.get('owner_id') != uid: continue
        fp = os.path.join(UPLOAD_DIR, info['stored_name'])
        if not os.path.exists(fp): continue
        if info.get('folder'): folders_set.add(info['folder'])
        type_counts[info.get('type', 'file')] = type_counts.get(info.get('type','file'), 0) + 1
        total_size_raw += info.get('size', 0)

        if q and q not in info['original_name'].lower() and q not in info.get('description','').lower() and q not in ' '.join(info.get('tags',[])).lower(): continue
        if ftype and info.get('type') != ftype: continue
        if folder and info.get('folder','') != folder: continue
        if show_starred and not info.get('is_starred'): continue

        result.append({**info, 'id': fid})

    if sort == 'newest': result.sort(key=lambda x: x.get('uploaded_at', 0), reverse=True)
    elif sort == 'oldest': result.sort(key=lambda x: x.get('uploaded_at', 0))
    elif sort == 'size_desc': result.sort(key=lambda x: x.get('size', 0), reverse=True)
    elif sort == 'size_asc': result.sort(key=lambda x: x.get('size', 0))
    elif sort == 'name': result.sort(key=lambda x: x.get('original_name', '').lower())
    elif sort == 'popular': result.sort(key=lambda x: x.get('views', 0) + x.get('downloads', 0), reverse=True)

    users = load_users()
    user = users.get(uid, {})
    used_bytes = user_storage_used(uid)
    quota_bytes = user.get('quota_mb', DEFAULT_QUOTA) * 1024 * 1024

    return render_template('index.html',
        files=result, q=q, ftype=ftype, sort=sort, folder=folder,
        show_starred=show_starred, folders=sorted(folders_set),
        type_counts=type_counts, total_size=fmt_size(total_size_raw),
        total_files=user_file_count(uid),
        used_bytes=used_bytes, quota_bytes=quota_bytes,
        local_ip=get_local_ip()
    )

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    uid = session['user_id']
    users = load_users()
    user = users.get(uid, {})
    quota_bytes = user.get('quota_mb', DEFAULT_QUOTA) * 1024 * 1024
    used = user_storage_used(uid)

    if 'file' not in request.files:
        flash('No file selected.', 'error'); return redirect(url_for('index'))

    uploaded_files = request.files.getlist('file')
    files_db = load_files()
    uploaded_ids = []
    folder = request.form.get('folder', '').strip()
    is_public = request.form.get('is_public') == '1'
    file_password = request.form.get('file_password', '').strip()
    expires_days = request.form.get('expires_days', '')

    for f in uploaded_files:
        if not f or not f.filename: continue
        original_name = f.filename
        ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
        fid = str(uuid.uuid4())[:14]
        stored_name = f"{fid}.{ext}" if ext else fid
        filepath = os.path.join(UPLOAD_DIR, stored_name)

        # Save first to check size
        f.save(filepath)
        size = os.path.getsize(filepath)

        # Quota check
        if used + size > quota_bytes:
            os.remove(filepath)
            flash(f'⚠ Quota exceeded! Cannot upload "{original_name}".', 'error')
            continue

        used += size
        ftype = file_type(original_name)
        mime, _ = mimetypes.guess_type(original_name)
        checksum = md5_file(filepath)

        # Duplicate detection
        dup = next((fid2 for fid2, fi in files_db.items() if fi.get('owner_id')==uid and fi.get('checksum')==checksum), None)
        if dup:
            os.remove(filepath)
            flash(f'"{original_name}" is a duplicate of an existing file.', 'warning')
            continue

        # Expiry
        expires_at = None
        if expires_days and expires_days.isdigit() and int(expires_days) > 0:
            expires_at = (datetime.now() + timedelta(days=int(expires_days))).timestamp()

        files_db[fid] = {
            'id': fid, 'owner_id': uid,
            'original_name': original_name, 'stored_name': stored_name,
            'size': size, 'type': ftype, 'mime': mime or 'application/octet-stream',
            'uploaded_at': datetime.now().timestamp(),
            'description': request.form.get('description', ''),
            'tags': [t.strip() for t in request.form.get('tags','').split(',') if t.strip()],
            'folder': folder, 'is_public': is_public,
            'file_password': generate_password_hash(file_password) if file_password else None,
            'expires_at': expires_at, 'is_starred': False,
            'downloads': 0, 'views': 0, 'checksum': checksum,
            'notes': '', 'rename_history': [],
            'bandwidth_served': 0,
        }
        uploaded_ids.append(fid)
        add_activity(uid, 'upload', original_name, fid)

    save_files(files_db)
    if uploaded_ids:
        flash(f'✓ {len(uploaded_ids)} file(s) uploaded!', 'success')
        if len(uploaded_ids) == 1:
            return redirect(url_for('file_view', fid=uploaded_ids[0]))
    return redirect(url_for('index'))

@app.route('/file/<fid>', methods=['GET', 'POST'])
def file_view(fid):
    check_expiry()
    files = load_files()
    if fid not in files: abort(404)
    info = files[fid]
    uid = session.get('user_id')
    is_owner = uid == info.get('owner_id')

    # Access control
    if not info.get('is_public') and not is_owner:
        if not uid:
            flash('Login to view this file.', 'info')
            return redirect(url_for('login', next=f'/file/{fid}'))
        abort(403)

    # Password check
    if info.get('file_password') and not is_owner:
        session_key = f'file_auth_{fid}'
        if request.method == 'POST':
            pwd = request.form.get('file_password', '')
            if check_password_hash(info['file_password'], pwd):
                session[session_key] = True
            else:
                flash('Wrong password.', 'error')
                return render_template('file_password.html', fid=fid, f=info)
        if not session.get(session_key):
            return render_template('file_password.html', fid=fid, f=info)

    # Increment views
    files[fid]['views'] = files[fid].get('views', 0) + 1
    save_files(files)

    if is_owner: add_activity(uid, 'view', info['original_name'], fid)

    host = request.host
    fp = os.path.join(UPLOAD_DIR, info['stored_name'])
    archive_contents = None
    if info['type'] == 'archive' and os.path.exists(fp):
        archive_contents = get_archive_contents(fp, info['stored_name'])

    users = load_users()
    owner = users.get(info.get('owner_id', ''), {})

    return render_template('file.html',
        f={**info, 'id': fid}, is_owner=is_owner,
        raw_url=f"http://{host}/raw/{fid}",
        host=host, archive_contents=archive_contents,
        owner=owner
    )

@app.route('/raw/<fid>')
def raw_file(fid):
    check_expiry()
    files = load_files()
    if fid not in files: abort(404)
    info = files[fid]
    uid = session.get('user_id')

    if not info.get('is_public') and uid != info.get('owner_id'):
        if not uid: abort(401)
        abort(403)
    if info.get('file_password') and uid != info.get('owner_id'):
        if not session.get(f'file_auth_{fid}'): abort(403)

    fp = os.path.join(UPLOAD_DIR, info['stored_name'])
    if not os.path.exists(fp): abort(404)

    mime = info.get('mime', 'application/octet-stream')
    file_size = os.path.getsize(fp)
    range_header = request.headers.get('Range')

    # Track bandwidth
    files[fid]['bandwidth_served'] = files[fid].get('bandwidth_served', 0) + file_size
    save_files(files)

    # Update user bandwidth
    if info.get('owner_id'):
        users = load_users()
        u = users.get(info['owner_id'], {})
        u['bandwidth_used'] = u.get('bandwidth_used', 0) + file_size
        users[info['owner_id']] = u
        save_users(users)

    if range_header:
        byte1, byte2 = 0, file_size - 1
        m = re.search(r'bytes=(\d+)-(\d*)', range_header)
        if m:
            byte1 = int(m.group(1))
            if m.group(2): byte2 = int(m.group(2))
        length = byte2 - byte1 + 1
        with open(fp, 'rb') as f:
            f.seek(byte1); data = f.read(length)
        resp = Response(data, 206, mimetype=mime)
        resp.headers['Content-Range'] = f'bytes {byte1}-{byte2}/{file_size}'
        resp.headers['Accept-Ranges'] = 'bytes'
        resp.headers['Content-Length'] = length
        resp.headers['Cache-Control'] = 'public, max-age=3600'
        return resp

    return send_file(fp, mimetype=mime)

@app.route('/download/<fid>')
def download(fid):
    files = load_files()
    if fid not in files: abort(404)
    info = files[fid]
    uid = session.get('user_id')

    if not info.get('is_public') and uid != info.get('owner_id'):
        abort(403)

    fp = os.path.join(UPLOAD_DIR, info['stored_name'])
    if not os.path.exists(fp): abort(404)
    files[fid]['downloads'] = files[fid].get('downloads', 0) + 1
    save_files(files)
    return send_file(fp, as_attachment=True, download_name=info['original_name'])

# ─── File Management Actions ─────────────────────────────────────────────────

@app.route('/delete/<fid>', methods=['POST'])
@login_required
def delete_file(fid):
    uid = session['user_id']
    files = load_files()
    if fid not in files: abort(404)
    if files[fid].get('owner_id') != uid and not load_users().get(uid,{}).get('is_admin'):
        abort(403)
    fp = os.path.join(UPLOAD_DIR, files[fid]['stored_name'])
    name = files[fid]['original_name']
    if os.path.exists(fp): os.remove(fp)
    del files[fid]
    save_files(files)
    add_activity(uid, 'delete', name)
    flash(f'"{name}" deleted.', 'success')
    return redirect(request.referrer or url_for('index'))

@app.route('/bulk-delete', methods=['POST'])
@login_required
def bulk_delete():
    uid = session['user_id']
    ids = request.form.getlist('selected_ids')
    files = load_files()
    count = 0
    for fid in ids:
        if fid in files and files[fid].get('owner_id') == uid:
            fp = os.path.join(UPLOAD_DIR, files[fid]['stored_name'])
            if os.path.exists(fp): os.remove(fp)
            del files[fid]; count += 1
    save_files(files)
    flash(f'{count} file(s) deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/bulk-move', methods=['POST'])
@login_required
def bulk_move():
    uid = session['user_id']
    ids = request.form.getlist('selected_ids')
    target_folder = request.form.get('target_folder', '').strip()
    files = load_files()
    count = 0
    for fid in ids:
        if fid in files and files[fid].get('owner_id') == uid:
            files[fid]['folder'] = target_folder; count += 1
    save_files(files)
    flash(f'{count} file(s) moved to "{target_folder or "root"}".', 'success')
    return redirect(url_for('index'))

@app.route('/rename/<fid>', methods=['POST'])
@login_required
def rename_file(fid):
    uid = session['user_id']
    files = load_files()
    if fid not in files or files[fid].get('owner_id') != uid: abort(403)
    new_name = request.form.get('new_name', '').strip()
    if not new_name: flash('Name required.', 'error'); return redirect(url_for('file_view', fid=fid))
    old_ext = files[fid]['original_name'].rsplit('.', 1)[-1] if '.' in files[fid]['original_name'] else ''
    new_ext = new_name.rsplit('.', 1)[-1] if '.' in new_name else ''
    if old_ext and not new_ext: new_name = f"{new_name}.{old_ext}"
    history = files[fid].get('rename_history', [])
    history.append({'from': files[fid]['original_name'], 'at': datetime.now().timestamp()})
    files[fid]['rename_history'] = history[-10:]
    files[fid]['original_name'] = new_name
    save_files(files)
    add_activity(uid, 'rename', f'→ {new_name}', fid)
    flash(f'Renamed to "{new_name}"', 'success')
    return redirect(url_for('file_view', fid=fid))

@app.route('/update/<fid>', methods=['POST'])
@login_required
def update_file(fid):
    uid = session['user_id']
    files = load_files()
    if fid not in files or files[fid].get('owner_id') != uid: abort(403)
    files[fid]['description'] = request.form.get('description', '')
    files[fid]['tags'] = [t.strip() for t in request.form.get('tags','').split(',') if t.strip()]
    files[fid]['folder'] = request.form.get('folder', '').strip()
    files[fid]['notes'] = request.form.get('notes', '')
    files[fid]['is_public'] = request.form.get('is_public') == '1'

    new_pwd = request.form.get('new_file_password', '').strip()
    remove_pwd = request.form.get('remove_password') == '1'
    if remove_pwd: files[fid]['file_password'] = None
    elif new_pwd: files[fid]['file_password'] = generate_password_hash(new_pwd)

    exp_days = request.form.get('expires_days', '').strip()
    if exp_days == '0' or exp_days == '': files[fid]['expires_at'] = None
    elif exp_days.isdigit():
        files[fid]['expires_at'] = (datetime.now() + timedelta(days=int(exp_days))).timestamp()

    save_files(files)
    flash('File updated!', 'success')
    return redirect(url_for('file_view', fid=fid))

@app.route('/star/<fid>', methods=['POST'])
@login_required
def star_file(fid):
    uid = session['user_id']
    files = load_files()
    if fid not in files or files[fid].get('owner_id') != uid: abort(403)
    files[fid]['is_starred'] = not files[fid].get('is_starred', False)
    save_files(files)
    state = 'starred' if files[fid]['is_starred'] else 'unstarred'
    return jsonify({'starred': files[fid]['is_starred'], 'msg': f'File {state}'})

@app.route('/toggle-public/<fid>', methods=['POST'])
@login_required
def toggle_public(fid):
    uid = session['user_id']
    files = load_files()
    if fid not in files or files[fid].get('owner_id') != uid: abort(403)
    files[fid]['is_public'] = not files[fid].get('is_public', False)
    save_files(files)
    return jsonify({'is_public': files[fid]['is_public']})

@app.route('/multi-download', methods=['POST'])
@login_required
def multi_download():
    uid = session['user_id']
    ids = request.form.getlist('selected_ids')
    files = load_files()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fid in ids:
            if fid in files and files[fid].get('owner_id') == uid:
                fp = os.path.join(UPLOAD_DIR, files[fid]['stored_name'])
                if os.path.exists(fp):
                    zf.write(fp, files[fid]['original_name'])
    buf.seek(0)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(buf, as_attachment=True, download_name=f'MediaVault_export_{ts}.zip',
                     mimetype='application/zip')

# ─── Archive Contents ─────────────────────────────────────────────────────────

def get_archive_contents(filepath, stored_name):
    contents = []
    try:
        ext = stored_name.rsplit('.', 1)[-1].lower()
        if ext == 'zip':
            with zipfile.ZipFile(filepath, 'r') as zf:
                for info in zf.infolist():
                    contents.append({'name': info.filename, 'size': fmt_size(info.file_size),
                                     'compressed': fmt_size(info.compress_size), 'is_dir': info.is_dir()})
        elif ext in ['tar','gz','bz2','xz']:
            with tarfile.open(filepath) as tf:
                for m in tf.getmembers():
                    contents.append({'name': m.name, 'size': fmt_size(m.size),
                                     'compressed': fmt_size(m.size), 'is_dir': m.isdir()})
    except Exception as e:
        contents = [{'name': f'Error: {e}', 'size': '', 'compressed': '', 'is_dir': False}]
    return contents

# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']
    files = load_files()
    users = load_users()
    user = users.get(uid, {})
    activity = [a for a in reversed(load_activity()) if a.get('uid') == uid][:20]

    types = {}; uploads_by_day = {}; total_dl = 0; total_views = 0; total_bw = 0
    file_list = []

    for fid, info in files.items():
        if info.get('owner_id') != uid: continue
        fp = os.path.join(UPLOAD_DIR, info['stored_name'])
        if not os.path.exists(fp): continue
        t = info.get('type', 'file')
        types[t] = types.get(t, 0) + 1
        day = datetime.fromtimestamp(info.get('uploaded_at', 0)).strftime('%Y-%m-%d')
        uploads_by_day[day] = uploads_by_day.get(day, 0) + 1
        total_dl += info.get('downloads', 0)
        total_views += info.get('views', 0)
        total_bw += info.get('bandwidth_served', 0)
        file_list.append({**info, 'id': fid})

    top_files = sorted(file_list, key=lambda x: x.get('views',0)+x.get('downloads',0), reverse=True)[:5]
    recent = sorted(file_list, key=lambda x: x.get('uploaded_at',0), reverse=True)[:5]

    return render_template('dashboard.html',
        total_files=user_file_count(uid),
        total_size=fmt_size(user_storage_used(uid)),
        used_bytes=user_storage_used(uid),
        quota_bytes=user.get('quota_mb', DEFAULT_QUOTA)*1024*1024,
        total_dl=total_dl, total_views=total_views,
        total_bw=fmt_size(total_bw),
        types=types, uploads_by_day=dict(sorted(uploads_by_day.items())[-14:]),
        top_files=top_files, recent=recent, activity=activity,
        user=user, local_ip=get_local_ip()
    )

# ─── QR Code ─────────────────────────────────────────────────────────────────

@app.route('/qr/<fid>')
def qr_code(fid):
    files = load_files()
    if fid not in files: abort(404)
    host = request.host
    url = f"http://{host}/file/{fid}"
    return render_template('qr.html', fid=fid, url=url, f=files[fid])

# ─── Share Info ───────────────────────────────────────────────────────────────

@app.route('/share-info/<fid>')
def share_info(fid):
    files = load_files()
    if fid not in files: abort(404)
    ip = get_local_ip()
    return jsonify({
        'local': f"http://localhost:5000/file/{fid}",
        'network': f"http://{ip}:5000/file/{fid}",
        'raw_local': f"http://localhost:5000/raw/{fid}",
        'raw_network': f"http://{ip}:5000/raw/{fid}",
        'file': files[fid]['original_name'],
        'type': files[fid]['type'],
    })

# ─── Profile & Settings ───────────────────────────────────────────────────────

@app.route('/profile')
@login_required
def profile():
    uid = session['user_id']
    users = load_users()
    user = users.get(uid, {})
    files = load_files()
    user_files = [f for f in files.values() if f.get('owner_id') == uid]
    public_files = [f for f in user_files if f.get('is_public')]
    starred = [f for f in user_files if f.get('is_starred')]
    activity = [a for a in reversed(load_activity()) if a.get('uid') == uid][:10]
    return render_template('profile.html',
        user=user, user_files=user_files, public_files=public_files,
        starred=starred, activity=activity,
        total_size=fmt_size(user_storage_used(uid))
    )

@app.route('/u/<username>')
def public_profile(username):
    users = load_users()
    user = next((u for u in users.values() if u['username'] == username.lower()), None)
    if not user: abort(404)
    files = load_files()
    pub_files = [f for f in files.values() if f.get('owner_id') == user['id'] and f.get('is_public') and not f.get('file_password')]
    pub_files.sort(key=lambda x: x.get('uploaded_at',0), reverse=True)
    return render_template('public_profile.html', user=user, files=pub_files,
                           total_size=fmt_size(user_storage_used(user['id'])))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    uid = session['user_id']
    users = load_users()
    user = users.get(uid, {})
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'profile':
            bio = request.form.get('bio', '').strip()[:200]
            email = request.form.get('email', '').strip().lower()
            users[uid]['bio'] = bio
            if email and '@' in email: users[uid]['email'] = email
            save_users(users)
            flash('Profile updated!', 'success')
        elif action == 'password':
            current = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm = request.form.get('confirm_password', '')
            if not check_password_hash(user['password_hash'], current):
                flash('Current password is wrong.', 'error')
            elif len(new_pw) < 6:
                flash('New password must be 6+ characters.', 'error')
            elif new_pw != confirm:
                flash('Passwords do not match.', 'error')
            else:
                users[uid]['password_hash'] = generate_password_hash(new_pw)
                save_users(users)
                flash('Password changed!', 'success')
        elif action == 'regen_token':
            users[uid]['api_token'] = 'tok_' + secrets.token_hex(20)
            save_users(users)
            flash('API token regenerated!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', user=users.get(uid, {}))

# ─── Admin Panel ──────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_panel():
    users = load_users()
    files = load_files()
    activity = list(reversed(load_activity()))[:30]
    user_stats = []
    for uid, u in users.items():
        user_stats.append({
            **u, 'file_count': sum(1 for f in files.values() if f.get('owner_id')==uid),
            'storage': fmt_size(user_storage_used(uid))
        })
    user_stats.sort(key=lambda x: x.get('created_at',0), reverse=True)
    total_size = sum(os.path.getsize(os.path.join(UPLOAD_DIR, f['stored_name']))
                     for f in files.values() if os.path.exists(os.path.join(UPLOAD_DIR, f['stored_name'])))
    return render_template('admin.html',
        users=user_stats, total_users=len(users),
        total_files=len(files), total_size=fmt_size(total_size),
        activity=activity, files_db=files, load_users=load_users
    )

@app.route('/admin/user/<uid>/toggle-admin', methods=['POST'])
@admin_required
def admin_toggle_admin(uid):
    if uid == session['user_id']: flash("Can't change your own admin status.", 'error'); return redirect(url_for('admin_panel'))
    users = load_users()
    if uid in users:
        users[uid]['is_admin'] = not users[uid].get('is_admin', False)
        save_users(users)
        flash(f'Admin status toggled for {users[uid]["username"]}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<uid>/delete', methods=['POST'])
@admin_required
def admin_delete_user(uid):
    if uid == session['user_id']: flash("Can't delete yourself.", 'error'); return redirect(url_for('admin_panel'))
    users = load_users()
    files = load_files()
    username = users.get(uid, {}).get('username', uid)
    # Delete user files
    for fid in [k for k,v in files.items() if v.get('owner_id')==uid]:
        fp = os.path.join(UPLOAD_DIR, files[fid]['stored_name'])
        if os.path.exists(fp): os.remove(fp)
        del files[fid]
    save_files(files)
    del users[uid]; save_users(users)
    flash(f'User "{username}" and all their files deleted.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/file/<fid>/delete', methods=['POST'])
@admin_required
def admin_delete_file(fid):
    files = load_files()
    if fid in files:
        fp = os.path.join(UPLOAD_DIR, files[fid]['stored_name'])
        if os.path.exists(fp): os.remove(fp)
        del files[fid]; save_files(files)
    flash('File deleted.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<uid>/set-quota', methods=['POST'])
@admin_required
def admin_set_quota(uid):
    users = load_users()
    quota_mb = request.form.get('quota_mb', '5120')
    if uid in users and quota_mb.isdigit():
        users[uid]['quota_mb'] = int(quota_mb)
        save_users(users)
        flash('Quota updated.', 'success')
    return redirect(url_for('admin_panel'))

# ─── REST API ─────────────────────────────────────────────────────────────────

def api_auth():
    token = request.headers.get('Authorization', '').replace('Bearer ', '') or request.args.get('token','')
    if not token: return None
    users = load_users()
    return next((u for u in users.values() if u.get('api_token') == token), None)

@app.route('/api/files')
def api_files():
    user = api_auth()
    uid = user['id'] if user else None
    files = load_files()
    host = request.host
    result = []
    for fid, info in files.items():
        if uid and info.get('owner_id') == uid:
            pass  # owner sees all
        elif info.get('is_public') and not info.get('file_password'):
            pass  # public files visible
        else:
            continue
        fp = os.path.join(UPLOAD_DIR, info['stored_name'])
        if not os.path.exists(fp): continue
        result.append({**info, 'id': fid, 'file_password': bool(info.get('file_password')),
            'raw_url': f"http://{host}/raw/{fid}",
            'view_url': f"http://{host}/file/{fid}",
            'download_url': f"http://{host}/download/{fid}",
            'size_formatted': fmt_size(info.get('size',0))
        })
    result.sort(key=lambda x: x.get('uploaded_at',0), reverse=True)
    return jsonify({'total': len(result), 'authenticated': bool(user), 'files': result})

@app.route('/api/file/<fid>')
def api_file_info(fid):
    user = api_auth()
    files = load_files()
    if fid not in files: return jsonify({'error': 'Not found'}), 404
    info = files[fid]
    uid = user['id'] if user else None
    if not info.get('is_public') and uid != info.get('owner_id'):
        return jsonify({'error': 'Unauthorized'}), 403
    host = request.host
    return jsonify({**info, 'id': fid, 'file_password': bool(info.get('file_password')),
        'raw_url': f"http://{host}/raw/{fid}",
        'view_url': f"http://{host}/file/{fid}",
        'download_url': f"http://{host}/download/{fid}",
        'size_formatted': fmt_size(info.get('size',0))
    })

@app.route('/api/upload', methods=['POST'])
def api_upload():
    user = api_auth()
    if not user: return jsonify({'error': 'API token required'}), 401
    if 'file' not in request.files: return jsonify({'error': 'No file'}), 400
    f = request.files['file']
    if not f or not f.filename: return jsonify({'error': 'Empty file'}), 400
    original_name = f.filename
    ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''
    fid = str(uuid.uuid4())[:14]
    stored_name = f"{fid}.{ext}" if ext else fid
    filepath = os.path.join(UPLOAD_DIR, stored_name)
    f.save(filepath)
    size = os.path.getsize(filepath)
    ftype = file_type(original_name)
    mime, _ = mimetypes.guess_type(original_name)
    files = load_files()
    files[fid] = {'id': fid, 'owner_id': user['id'], 'original_name': original_name,
        'stored_name': stored_name, 'size': size, 'type': ftype,
        'mime': mime or 'application/octet-stream', 'uploaded_at': datetime.now().timestamp(),
        'description': request.form.get('description',''), 'tags': [],
        'folder': '', 'is_public': False, 'file_password': None, 'expires_at': None,
        'is_starred': False, 'downloads': 0, 'views': 0,
        'checksum': md5_file(filepath), 'notes': '', 'rename_history': [], 'bandwidth_served': 0,
    }
    save_files(files)
    host = request.host
    return jsonify({'success': True, 'id': fid,
        'raw_url': f"http://{host}/raw/{fid}",
        'view_url': f"http://{host}/file/{fid}",
        'download_url': f"http://{host}/download/{fid}",
        'name': original_name, 'size': fmt_size(size), 'type': ftype,
    }), 201

@app.route('/api/me')
def api_me():
    user = api_auth()
    if not user: return jsonify({'error': 'Unauthorized'}), 401
    uid = user['id']
    return jsonify({
        'id': uid, 'username': user['username'], 'email': user['email'],
        'is_admin': user.get('is_admin', False),
        'file_count': user_file_count(uid),
        'storage_used': fmt_size(user_storage_used(uid)),
        'quota': fmt_size(user.get('quota_mb', DEFAULT_QUOTA)*1024*1024),
        'bandwidth_used': fmt_size(user.get('bandwidth_used', 0)),
        'member_since': fmt_date(user.get('created_at', 0)),
    })

@app.route('/api/search')
def api_search():
    user = api_auth()
    uid = user['id'] if user else None
    q = request.args.get('q','').lower()
    files = load_files()
    host = request.host
    results = []
    for fid, info in files.items():
        if uid and info.get('owner_id') == uid: pass
        elif info.get('is_public') and not info.get('file_password'): pass
        else: continue
        if q and q not in info['original_name'].lower() and q not in info.get('description','').lower(): continue
        fp = os.path.join(UPLOAD_DIR, info['stored_name'])
        if not os.path.exists(fp): continue
        results.append({**info, 'id': fid, 'file_password': bool(info.get('file_password')),
            'raw_url': f"http://{host}/raw/{fid}"})
    return jsonify({'query': q, 'count': len(results), 'results': results})

# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e): return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e): return render_template('403.html'), 403

@app.errorhandler(413)
def too_large(e): flash('File too large (max 10 GB)', 'error'); return redirect(url_for('index'))

# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    ip = get_local_ip()
    print("\n" + "═"*60)
    print("  🎬  MediaVault Pro — Professional File Hosting")
    print("═"*60)
    print(f"  📍  Local:    http://localhost:5000")
    print(f"  🌐  Network:  http://{ip}:5000")
    print(f"  📁  Data:     {DATA_DIR}")
    print(f"  📦  Uploads:  {UPLOAD_DIR}")
    print("═"*60)
    print("  First user to register becomes Admin\n")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
