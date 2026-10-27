"""SIJAN MOD IOS Flask backend: private uploads, SQLite records, protected admin."""
import os, secrets, sqlite3, uuid, plistlib
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote
from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

load_dotenv()
BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get('DATA_DIR', BASE / 'instance')).resolve()
UPLOADS = DATA / 'uploads'
DB_PATH = Path(os.environ.get('DATABASE_PATH', DATA / 'sijan_store.sqlite3'))
MAX_MB = int(os.environ.get('MAX_UPLOAD_MB', '250'))
DEV = os.environ.get('APP_ENV', 'development').lower() == 'development'
if not DEV and not os.environ.get('SECRET_KEY'):
 raise RuntimeError('Set a persistent SECRET_KEY before production startup')
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or ('dev-only-' + secrets.token_hex(32)), MAX_CONTENT_LENGTH=MAX_MB*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','0') == '1')
CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri=os.environ.get('RATELIMIT_STORAGE_URI','memory://'))
KINDS = {
 'apps': ('apps','ipa',{'.ipa'},True), 'dns': ('dns_profiles','profile',{'.mobileconfig'},True),
 'certificates': ('certificates','certificate',{'.cer','.crt','.p12','.pfx'},False),
 'provisions': ('provisions','provision',{'.mobileprovision'},False)
}
SCHEMA = '''
CREATE TABLE IF NOT EXISTS apps(id INTEGER PRIMARY KEY,name TEXT NOT NULL,version TEXT NOT NULL,bundle_id TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',category TEXT NOT NULL DEFAULT 'ESign',manifest_url TEXT NOT NULL DEFAULT '',external_url TEXT NOT NULL DEFAULT '',file_key TEXT NOT NULL,icon_key TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dns_profiles(id INTEGER PRIMARY KEY,name TEXT NOT NULL,version TEXT NOT NULL DEFAULT '',description TEXT NOT NULL DEFAULT '',source TEXT NOT NULL DEFAULT '',purpose TEXT NOT NULL DEFAULT '',icon_key TEXT NOT NULL DEFAULT '',file_key TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY,label TEXT NOT NULL,cert_type TEXT NOT NULL,expires_at TEXT NOT NULL DEFAULT '',organization TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'unverified',notes TEXT NOT NULL DEFAULT '',file_key TEXT NOT NULL,is_private INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS provisions(id INTEGER PRIMARY KEY,name TEXT NOT NULL,bundle_id TEXT NOT NULL DEFAULT '',team_id TEXT NOT NULL DEFAULT '',expires_at TEXT NOT NULL DEFAULT '',distribution TEXT NOT NULL DEFAULT 'unknown',status TEXT NOT NULL DEFAULT 'unverified',notes TEXT NOT NULL DEFAULT '',file_key TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_state(id INTEGER PRIMARY KEY CHECK(id=1),password_hash TEXT NOT NULL,must_change INTEGER NOT NULL DEFAULT 1);
'''
def db():
 DATA.mkdir(parents=True,exist_ok=True); c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row; return c
def init_db():
 for folder in ('public','private','icons'): (UPLOADS/folder).mkdir(parents=True,exist_ok=True)
 with db() as c:
  c.executescript(SCHEMA)
  if not c.execute('SELECT id FROM admin_state WHERE id=1').fetchone():
   initial=os.environ.get('ADMIN_PASSWORD') or ('sijan' if DEV else '')
   if not DEV and initial == 'sijan': raise RuntimeError('The development password is forbidden in production; configure a strong ADMIN_PASSWORD')
   if not initial and not os.environ.get('ADMIN_PASSWORD_HASH'): raise RuntimeError('Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH before production first start')
   hashed=os.environ.get('ADMIN_PASSWORD_HASH') or generate_password_hash(initial)
   c.execute('INSERT INTO admin_state(id,password_hash,must_change) VALUES(1,?,1)',(hashed,)); c.commit()
def admin(fn):
 @wraps(fn)
 def wrapped(*a,**kw):
  if not session.get('admin'):
   if request.path.startswith('/api/'): return jsonify(error='Authentication required'),401
   return redirect(url_for('login'))
  if request.path not in ('/dashboard','/api/password','/logout'):
   with db() as c: must=c.execute('SELECT must_change FROM admin_state WHERE id=1').fetchone()[0]
   if must: return jsonify(error='Change the initial password before managing store content'),403
  return fn(*a,**kw)
 return wrapped
def textval(key,label,limit=500,required=False):
 v=(request.form.get(key) or '').strip()
 if required and not v: raise ValueError(label+' is required')
 if len(v)>limit: raise ValueError(label+' is too long')
 return v
def store_file(field,extensions,folder,required=True):
 f=request.files.get(field)
 if not f or not f.filename:
  if required: raise ValueError(field+' file is required')
  return ''
 suffix=Path(secure_filename(f.filename)).suffix.lower()
 if suffix not in extensions: raise ValueError('Unsupported file type for '+field)
 key=folder+'/'+uuid.uuid4().hex+suffix
 if folder=='private':
  secret=os.environ.get('PRIVATE_STORAGE_KEY')
  if not secret: raise ValueError('PRIVATE_STORAGE_KEY must be set before storing private files')
  try: payload=Fernet(secret.encode()).encrypt(f.read())
  except Exception: raise ValueError('PRIVATE_STORAGE_KEY is invalid; generate a Fernet key')
  (UPLOADS/key).write_bytes(payload)
 else: f.save(UPLOADS/key)
 return key
def remove_file(key):
 if key:
  p=(UPLOADS/key).resolve()
  if UPLOADS.resolve() in p.parents and p.is_file(): p.unlink(missing_ok=True)
@app.after_request
def headers(r):
 r.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin','Content-Security-Policy':"default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})
 if request.is_secure: r.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
 return r
@app.get('/')
def home(): return render_template('index.html')
@app.get('/admin')
def login(): return redirect(url_for('dashboard')) if session.get('admin') else render_template('login.html')
@app.post('/login')
@limiter.limit('5 per minute')
def do_login():
 with db() as c: row=c.execute('SELECT password_hash FROM admin_state WHERE id=1').fetchone()
 if row and check_password_hash(row[0],request.form.get('password','')):
  session.clear(); session['admin']=True; return redirect(url_for('dashboard'))
 flash('Incorrect password. Please try again.','error'); return redirect(url_for('login'))
@app.post('/logout')
@admin
def logout(): session.clear(); return redirect(url_for('home'))
@app.get('/dashboard')
@admin
def dashboard():
 with db() as c:
  must=bool(c.execute('SELECT must_change FROM admin_state WHERE id=1').fetchone()[0])
  counts={k:c.execute('SELECT COUNT(*) FROM '+t).fetchone()[0] for k,(t,_,_,_) in KINDS.items()}
  recent=[]
  for k,(t,_,_,_) in KINDS.items():
   col='label' if k=='certificates' else 'name'
   recent += [{'kind':k,'label':x[0],'created_at':x[1]} for x in c.execute(f'SELECT {col},created_at FROM {t} ORDER BY id DESC LIMIT 4')]
 recent.sort(key=lambda x:x['created_at'],reverse=True)
 return render_template('dashboard.html',counts=counts,recent=recent[:8],must_change=must)
@app.post('/api/password')
@admin
def change_password():
 old=request.form.get('old_password',''); new=request.form.get('new_password','')
 if len(new)<12: return jsonify(error='Use at least 12 characters for the new password'),400
 with db() as c:
  row=c.execute('SELECT password_hash FROM admin_state WHERE id=1').fetchone()
  if not check_password_hash(row[0],old): return jsonify(error='Current password is incorrect'),400
  c.execute('UPDATE admin_state SET password_hash=?,must_change=0 WHERE id=1',(generate_password_hash(new),)); c.commit()
 return jsonify(ok=True)
@app.get('/api/public')
def public_api():
 with db() as c:
  apps=[dict(x) for x in c.execute('SELECT id,name,version,bundle_id,description,category,manifest_url,external_url,icon_key FROM apps WHERE enabled=1 ORDER BY id DESC')]
  dns=[dict(x) for x in c.execute('SELECT id,name,version,description,source,purpose,icon_key FROM dns_profiles WHERE enabled=1 ORDER BY id DESC')]
 # Include the bundled ESign IPA as a built-in storefront card when deployed.
 if (Path(app.static_folder or BASE/'static')/'ESign.ipa').is_file():
  apps.append({'id':0,'name':'ESign','version':'2.0','bundle_id':'p3.xyz.yyyue.esign',
   'description':'Install ESign on iPhone.','category':'ESign','manifest_url':url_for('esign_manifest',_external=True),
   'external_url':url_for('static',filename='ESign.ipa',_external=True),'icon_key':''})
 for x in apps:
  x['icon_url']=url_for('icon',key=x.pop('icon_key'),_external=True) if x['icon_key'] else ''
  x['download_url']=x.pop('external_url') or url_for('download',kind='apps',item_id=x['id'],_external=True)
  manifest_url=x.pop('manifest_url') or url_for('app_manifest',item_id=x['id'],_external=True)
  x['install_url']='itms-services://?action=download-manifest&url='+quote(manifest_url,safe='')
 for x in dns:
  x['icon_url']=url_for('icon',key=x.pop('icon_key'),_external=True) if x['icon_key'] else ''
  x['download_url']='https://release-assets.githubusercontent.com/github-production-release-asset/1224449257/b611e007-61a8-4208-b6a5-2fdb01c9415d?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-10-27T17%3A35%3A52Z&rscd=attachment%3B+filename%3Dkhoindvn.mobileconfig&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2026-10-27T16%3A35%3A11Z&ske=2026-10-27T17%3A35%3A52Z&sks=b&skv=2018-11-09&sig=uiObCzW8t50RNYzms%2FQJmZdTserc9llM1m4ZUmtCNDc%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc5MzEyMDY3MiwibmJmIjoxNzkzMTIwMzcyLCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.eAOVRVdg1wdVD4p7yL2FKJN9TI9EnkGSCBHG__Ek8hw&response-content-disposition=attachment%3B%20filename%3Dkhoindvn.mobileconfig&response-content-type=application%2Foctet-stream'
 with db() as c: settings={r[0]:r[1] for r in c.execute("SELECT key,value FROM settings WHERE key IN ('announcement','announcement_url','discord_url','telegram_url')")}
 return jsonify(apps=apps,dns_profiles=dns,settings=settings)
@app.get('/files/<kind>/<int:item_id>')
def download(kind,item_id):
 if kind not in ('apps','dns'): abort(404)
 t=KINDS[kind][0]
 with db() as c: row=c.execute(f'SELECT file_key FROM {t} WHERE id=? AND enabled=1',(item_id,)).fetchone()
 if not row: abort(404)
 return send_file(UPLOADS/row[0],as_attachment=True,download_name=Path(row[0]).name)
@app.get('/manifest/<int:item_id>.plist')
def app_manifest(item_id):
 with db() as c:
  row=c.execute('SELECT name,version,bundle_id,external_url,file_key FROM apps WHERE id=? AND enabled=1',(item_id,)).fetchone()
 if not row: abort(404)
 ipa_url=row['external_url'] or url_for('download',kind='apps',item_id=item_id,_external=True)
 manifest={'items':[{'assets':[{'kind':'software-package','url':ipa_url}],
  'metadata':{'bundle-identifier':row['bundle_id'],'bundle-version':row['version'],'kind':'software','title':row['name']}}]}
 return Response(plistlib.dumps(manifest,fmt=plistlib.FMT_XML),mimetype='application/xml')
@app.get('/manifest/esign.plist')
def esign_manifest():
 ipa_path=Path(app.static_folder or BASE/'static')/'ESign.ipa'
 if not ipa_path.is_file(): abort(404)
 manifest={'items':[{'assets':[{'kind':'software-package','url':url_for('static',filename='ESign.ipa',_external=True)}],
  'metadata':{'bundle-identifier':'p3.xyz.yyyue.esign','bundle-version':'2.0','kind':'software','title':'ESign'}}]}
 return Response(plistlib.dumps(manifest,fmt=plistlib.FMT_XML),mimetype='application/xml')
@app.get('/icons/<path:key>')
def icon(key):
 if '/' in key or '..' in key: abort(404)
 p=(UPLOADS/'icons'/key).resolve()
 if UPLOADS.resolve() not in p.parents or not p.is_file(): abort(404)
 return send_file(p,conditional=True,max_age=3600)
@app.get('/api/admin/<kind>')
@admin
def list_records(kind):
 if kind not in KINDS: abort(404)
 with db() as c: rows=c.execute('SELECT * FROM '+KINDS[kind][0]+' ORDER BY id DESC').fetchall()
 result=[]
 for row in rows:
  d=dict(row)
  for secret in ('file_key','icon_key','is_private'): d.pop(secret,None)
  result.append(d)
 return jsonify(items=result)
@app.post('/api/admin/<kind>')
@admin
def add_record(kind):
 if kind not in KINDS: abort(404)
 file_key=icon_key=''
 try:
  table,field,exts,_=KINDS[kind]; file_key=store_file(field,exts,'private' if kind in ('certificates','provisions') else 'public')
  icon_key=store_file('icon',{'.png','.jpg','.jpeg','.webp'},'icons',False); now=datetime.now(timezone.utc).isoformat()
  if kind=='apps':
   vals=(textval('name','Name',120,True),textval('version','Version',40,True),textval('bundle_id','Bundle ID',200,True),textval('description','Description',3000),textval('category','Category',40),textval('manifest_url','Manifest URL',1000),textval('external_url','External URL',1000),file_key,icon_key,int(request.form.get('enabled')=='1'),now)
   if any(v and not v.startswith('https://') for v in vals[5:7]): raise ValueError('URLs must use HTTPS')
   sql='INSERT INTO apps(name,version,bundle_id,description,category,manifest_url,external_url,file_key,icon_key,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)'
  elif kind=='dns':
   vals=(textval('name','Name',120,True),textval('version','Version',40),textval('description','Description',3000),textval('source','Source',250),textval('purpose','Purpose',500),icon_key,file_key,int(request.form.get('enabled')=='1'),now)
   sql='INSERT INTO dns_profiles(name,version,description,source,purpose,icon_key,file_key,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?)'
  elif kind=='certificates':
   vals=(textval('label','Label',120,True),textval('cert_type','Certificate type',20,True),textval('expires_at','Expiration',40),textval('organization','Organization',200),textval('status','Status',40),textval('notes','Notes',3000),file_key,int(Path(file_key).suffix.lower() in ('.p12','.pfx')),now)
   sql='INSERT INTO certificates(label,cert_type,expires_at,organization,status,notes,file_key,is_private,created_at) VALUES(?,?,?,?,?,?,?,?,?)'
  else:
   vals=(textval('name','Name',120,True),textval('bundle_id','Bundle ID',200),textval('team_id','Team ID',100),textval('expires_at','Expiration',40),textval('distribution','Distribution',40),textval('status','Status',40),textval('notes','Notes',3000),file_key,now)
   sql='INSERT INTO provisions(name,bundle_id,team_id,expires_at,distribution,status,notes,file_key,created_at) VALUES(?,?,?,?,?,?,?,?,?)'
  with db() as c: c.execute(sql,vals); c.commit()
  return jsonify(ok=True),201
 except ValueError as e:
  remove_file(file_key); remove_file(icon_key); return jsonify(error=str(e)),400
@app.put('/api/admin/<kind>/<int:item_id>')
@admin
def edit_record(kind,item_id):
 if kind not in KINDS: abort(404)
 table,field,exts,_=KINDS[kind]
 try:
  with db() as c:
   old=c.execute('SELECT * FROM '+table+' WHERE id=?',(item_id,)).fetchone()
   if not old: abort(404)
   changes={}
   if kind=='apps':
    for k,label,lim,req in [('name','Name',120,True),('version','Version',40,True),('bundle_id','Bundle ID',200,True),('description','Description',3000,False),('category','Category',40,False),('manifest_url','Manifest URL',1000,False),('external_url','External URL',1000,False)]: changes[k]=textval(k,label,lim,req)
    if any(v and not v.startswith('https://') for k,v in changes.items() if k in ('manifest_url','external_url')): raise ValueError('URLs must use HTTPS')
    changes['enabled']=int(request.form.get('enabled')=='1')
   elif kind=='dns':
    for k,label,lim in [('name','Name',120),('version','Version',40),('description','Description',3000),('source','Source',250),('purpose','Purpose',500)]: changes[k]=textval(k,label,lim,k=='name')
    changes['enabled']=int(request.form.get('enabled')=='1')
   elif kind=='certificates':
    for k,label,lim in [('label','Label',120),('cert_type','Certificate type',20),('expires_at','Expiration',40),('organization','Organization',200),('status','Status',40),('notes','Notes',3000)]: changes[k]=textval(k,label,lim,k in ('label','cert_type'))
   else:
    for k,label,lim in [('name','Name',120),('bundle_id','Bundle ID',200),('team_id','Team ID',100),('expires_at','Expiration',40),('distribution','Distribution',40),('status','Status',40),('notes','Notes',3000)]: changes[k]=textval(k,label,lim,k=='name')
   newfile=store_file(field,exts,'private' if kind in ('certificates','provisions') else 'public',False)
   newicon=store_file('icon',{'.png','.jpg','.jpeg','.webp'},'icons',False) if kind in ('apps','dns') else ''
   if newfile: changes['file_key']=newfile
   if newicon: changes['icon_key']=newicon
   if kind=='certificates': changes['is_private']=int(Path(changes.get('file_key',old['file_key'])).suffix.lower() in ('.p12','.pfx'))
   sql='UPDATE '+table+' SET '+','.join(k+'=?' for k in changes)+' WHERE id=?'
   c.execute(sql,tuple(changes.values())+(item_id,)); c.commit()
  if newfile: remove_file(old['file_key'])
  if newicon: remove_file(old['icon_key'])
  return jsonify(ok=True)
 except ValueError as e:
  if 'newfile' in locals(): remove_file(newfile)
  if 'newicon' in locals(): remove_file(newicon)
  return jsonify(error=str(e)),400
@app.delete('/api/admin/<kind>/<int:item_id>')
@admin
def delete_record(kind,item_id):
 if kind not in KINDS: abort(404)
 table=KINDS[kind][0]
 with db() as c:
  row=c.execute('SELECT * FROM '+table+' WHERE id=?',(item_id,)).fetchone()
  if not row: abort(404)
  remove_file(row['file_key'])
  if kind in ('apps','dns'): remove_file(row['icon_key'])
  c.execute('DELETE FROM '+table+' WHERE id=?',(item_id,)); c.commit()
 return jsonify(ok=True)
@app.get('/api/admin/settings')
@admin
def settings():
 with db() as c: data={r[0]:r[1] for r in c.execute('SELECT key,value FROM settings')}
 return jsonify(settings=data)
@app.post('/api/admin/settings')
@admin
def update_settings():
 allowed={'announcement','announcement_url','discord_url','telegram_url'}
 with db() as c:
  for k,v in request.form.items():
   if k in allowed:
    if k.endswith('_url') and v and not v.startswith('https://'): return jsonify(error='Links must use HTTPS'),400
    c.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(k,v[:1000]))
  c.commit()
 return jsonify(ok=True)
@app.errorhandler(413)
def too_large(_): return jsonify(error=f'Upload exceeds {MAX_MB} MB limit'),413
init_db()
if __name__=='__main__': app.run(host=os.environ.get('HOST','127.0.0.1'),port=int(os.environ.get('PORT','5000')),debug=DEV)
