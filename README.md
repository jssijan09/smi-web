# SIJAN MOD IOS

A Flask + SQLite application with a public catalogue and authenticated administration for IPA files, DNS configuration profiles, signing certificate records, and provisioning profile records. Uploads live under `DATA_DIR/uploads`, outside Flask's static directory. Sensitive certificate and provisioning files are Fernet-encrypted before they are written. Public downloads are limited to enabled IPA/DNS records; private files have no download route.

## Local development

Requires Python 3.10+.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the generated value in `PRIVATE_STORAGE_KEY` in `.env`. Set a random `SECRET_KEY` as well. The initial development administrator password is `sijan`; it is processed only by the server and stored as a password hash. On first admin visit use Security to set a unique password of at least 12 characters. Until changed, content management APIs are locked.

```powershell
python app.py
```

Open `http://127.0.0.1:5000`. Development cookies are not marked Secure on localhost. Do not expose development mode to the internet.

## Production deployment

Use a Python hosting service or Linux VM that supports persistent storage and a WSGI process. Static-only hosting cannot run this backend. Put the app behind a reverse proxy/load balancer that terminates HTTPS, configure the domain's DNS to the host, and issue a trusted TLS certificate (for example, with the host's managed TLS or Let's Encrypt). Enforce HTTPS at the proxy and set:

```dotenv
APP_ENV=production
SECRET_KEY=<long-random-secret>
ADMIN_PASSWORD=<unique-long-initial-password>
PRIVATE_STORAGE_KEY=<Fernet key generated once and backed up securely>
COOKIE_SECURE=1
DATA_DIR=/var/lib/sijan-store
DATABASE_PATH=/var/lib/sijan-store/sijan_store.sqlite3
MAX_UPLOAD_MB=250
RATELIMIT_STORAGE_URI=redis://127.0.0.1:6379/0
```

Generate a Fernet key with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Preserve it securely: losing it makes encrypted private uploads unrecoverable. Keep `.env`, the key, database, and uploads outside the source repository and web root. Set filesystem ownership/permissions so only the service account can read `DATA_DIR`. Configure proxy request body limits to match `MAX_UPLOAD_MB`.

Create a venv, install `requirements.txt`, set the environment above, then start with a production WSGI server, for example `gunicorn --workers 2 --bind 127.0.0.1:8000 app:app`. Startup initializes the SQLite schema. Use a single server or shared Redis limiter storage for rate limiting; Flask-Limiter's default in-memory development storage is not shared between workers. After first login, change the initial password before managing content. Do not set the development password in production.

Back up the SQLite database and upload tree together, plus a separately protected copy of `PRIVATE_STORAGE_KEY`. Use encrypted off-host backups and test restoration. A restore without the matching key cannot recover private certificate/profile files.

## Admin and API behavior

- `/admin` is the same-site admin login. All admin APIs require the signed session and CSRF token; login is rate limited. Cookies are HttpOnly and SameSite=Lax, and Secure in production configuration.
- `/api/public` returns only enabled public app/profile fields. It does not disclose filesystem keys, certificate records, provisioning records, or credentials.
- `/api/admin/apps`, `/dns`, `/certificates`, and `/provisions` support authenticated list/create, edit via `PUT /api/admin/<kind>/<id>`, and delete. IPA/profile files are served only if the corresponding record is enabled.
- Certificate `.p12`/`.pfx` and provisioning profile files are encrypted at rest and have no public or administrator file-download endpoint. Uploading records does not sign an IPA.
- Public records can be published by enabling them at creation or editing their record. The public site fetches these records dynamically; no HTML redeployment is needed.

The current upload validation checks allowed filename extensions and enforces the request size limit. The site does not re-sign uploaded IPAs. For each enabled IPA record, it generates an Apple OTA manifest automatically when no custom manifest URL is provided; the manifest points to the uploaded IPA or configured external HTTPS URL. The supplied ESign.ipa is bundled in `static/` and appears as an ESign card with an Install on iPhone action. Its embedded provisioning profile is expired and does not match its bundle identifier, so iOS may refuse installation; the website does not change or bypass the IPA's signature or provisioning profile.

The public DNS profile action opens the SIJAN MOD IOS AntiRevoke `.mobileconfig` download from the supplied signed GitHub release asset URL. This signed URL expires at 2026-10-27 17:35:52 UTC and must be replaced with a fresh asset URL after expiry: https://release-assets.githubusercontent.com/github-production-release-asset/1224449257/b611e007-61a8-4208-b6a5-2fdb01c9415d?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-10-27T17%3A35%3A52Z&rscd=attachment%3B+filename%3Dkhoindvn.mobileconfig&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2026-10-27T16%3A35%3A11Z&ske=2026-10-27T17%3A35%3A52Z&sks=b&skv=2018-11-09&sig=uiObCzW8t50RNYzms%2FQJmZdTserc9llM1m4ZUmtCNDc%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc5MzEyMDY3MiwibmJmIjoxNzkzMTIwMzcyLCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.eAOVRVdg1wdVD4p7yL2FKJN9TI9EnkGSCBHG__Ek8hw&response-content-disposition=attachment%3B%20filename%3Dkhoindvn.mobileconfig&response-content-type=application%2Foctet-stream. Users may need to open iOS Settings and complete profile installation explicitly; the site does not install profiles silently. DNS profile records remain available in the admin catalogue.

## Data and security notes

The development password is initialized only when the database is first created. If you need to reset it, stop the app and use a controlled database recovery procedure; do not expose a reset endpoint. Store secrets outside the repository. Configure production `SECRET_KEY`, `PRIVATE_STORAGE_KEY`, and `ADMIN_PASSWORD` before initial startup. HTTPS, host firewall rules, OS patching, backup security, and deployment hardening remain operator responsibilities.
