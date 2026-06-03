#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ECBU Liaison Pro - serveur cloud stable avec PostgreSQL/SQLite.
Démarrage Render: python server.py --host 0.0.0.0 --port $PORT
"""
import os, json, csv, io, hmac, base64, secrets, hashlib, datetime as dt, argparse, smtplib, ssl, random
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, request, redirect, session, Response, render_template_string, abort

APP_NAME = "ECBU Liaison Pro"
ADMIN_EMAIL = "medesse@admin.lab"
ADMIN_PASSWORD = "Med12369"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SECRET_KEY = os.environ.get("ECBU_SECRET", "ecbu-secret-change-me-" + secrets.token_hex(16))

# Configuration email pour la vérification des comptes.
# À renseigner dans Render > Environment.
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@ecbu-liaison.local").strip()
BASE_URL = os.environ.get("BASE_URL", "https://ecbu-liaison-pro.onrender.com").rstrip("/")
EMAIL_CODE_TTL_MINUTES = 60

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=bool(DATABASE_URL))

USE_PG = DATABASE_URL.startswith("postgres")
if USE_PG:
    import psycopg
    from psycopg.rows import dict_row
else:
    import sqlite3

ANTIBIOTICS = [
    "Ampicilline (AMP10)", "Amoxicilline + acide clavulanique (AMC30)", "Pipéracilline/Tazobactam (TZP)",
    "Ceftriaxone (CRO30)", "Ceftazidime (CAZ30)", "Céfotaxime (CTX30)", "Céfoxitine (FOX30)",
    "Imipénème (IPM10)", "Méropénème (MEM10)", "Ertapénème (ETP10)", "Gentamicine (GEN10)",
    "Amikacine (AK30)", "Tobramycine (TOB10)", "Ciprofloxacine (CIP5)", "Norfloxacine (NOR10)",
    "Ofloxacine (OFX5)", "Lévofloxacine (LEV5)", "Cotrimoxazole (SXT25)", "Nitrofurantoïne (F/M300)",
    "Fosfomycine (FOS200)", "Doxycycline (DO30)", "Azithromycine (AZM15)", "Erythromycine (E15)",
    "Clindamycine (DA2)", "Vancomycine (VA30)", "Linézolide (LZD10)"
]

RULES = [
    ("patient_informe", "Patient informé des conditions de prélèvement"),
    ("technique_maitrisee", "Technique de prélèvement maîtrisée par le patient"),
    ("toilette", "Toilette intime réalisée"),
    ("flacon_sterile", "Flacon stérile utilisé"),
    ("flacon_identifie", "Flacon correctement identifié"),
    ("volume_suffisant", "Volume d’urines suffisant"),
    ("absence_fuite", "Absence de fuite / flacon non souillé"),
    ("delai_conforme", "Délai miction–réception conforme"),
    ("temperature_conforme", "Température/conservation conforme"),
    ("transport_conforme", "Conditions de transport conformes"),
    ("nature_conforme", "Nature/type de prélèvement conforme"),
    ("antibiotherapie_renseignee", "Antibiothérapie renseignée"),
]

def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def db():
    if USE_PG:
        con = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return con
    con = sqlite3.connect("ecbu_liaison.db")
    con.row_factory = sqlite3.Row
    return con

def q(sql):
    return sql.replace("?", "%s") if USE_PG else sql

def rows(cur):
    data = cur.fetchall()
    return [dict(x) for x in data]

def one(cur):
    r = cur.fetchone()
    return dict(r) if r else None

def execute(sql, params=(), fetch=False, fetchone=False):
    con = db()
    try:
        cur = con.cursor()
        cur.execute(q(sql), params)
        if fetchone:
            result = one(cur)
        elif fetch:
            result = rows(cur)
        else:
            result = None
        con.commit()
        return result
    finally:
        con.close()

def hash_password(pwd, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 180000)
    return salt + "$" + base64.b64encode(digest).decode()

def verify_password(stored, pwd):
    try:
        salt, digest = stored.split("$", 1)
        return hmac.compare_digest(hash_password(pwd, salt).split("$", 1)[1], digest)
    except Exception:
        return False

def send_confirmation_email(to_email, code):
    if not SMTP_USER or not SMTP_PASSWORD:
        raise RuntimeError("SMTP non configuré. Ajoutez SMTP_USER et SMTP_PASSWORD dans Render > Environment.")
    subject = "Code de vérification ECBU Liaison Pro"
    body = f"""Bonjour,

Votre code de vérification ECBU Liaison Pro est : {code}

Ce code est valable pendant 1 heure.
Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.

ECBU Liaison Pro
{BASE_URL}
"""
    msg = (
        f"From: {SMTP_FROM}\r\n"
        f"To: {to_email}\r\n"
        f"Subject: {subject}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        f"{body}"
    )
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, [to_email], msg.encode("utf-8"))

def create_email_code(email):
    code = f"{random.randint(100000, 999999)}"
    code_hash = hash_password(code)
    expires = (dt.datetime.now() + dt.timedelta(minutes=EMAIL_CODE_TTL_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    execute("DELETE FROM email_verifications WHERE email=?", (email,))
    execute("INSERT INTO email_verifications(email, code_hash, expires_at, used, created_at) VALUES(?,?,?,?,?)",
            (email, code_hash, expires, 0, now()))
    return code

def verify_email_code(email, code):
    row = execute("SELECT * FROM email_verifications WHERE email=? AND used=0 ORDER BY id DESC LIMIT 1", (email,), fetchone=True)
    if not row:
        return False, "Aucun code valide trouvé pour cet email."
    if str(row.get("expires_at") or "") < now():
        return False, "Le code a expiré. Demandez un nouveau code."
    if not verify_password(row.get("code_hash", ""), code):
        return False, "Code de vérification incorrect."
    execute("UPDATE email_verifications SET used=1 WHERE id=?", (row["id"],))
    return True, "Email vérifié."

def init_db():
    if USE_PG:
        ddl = [
            """CREATE TABLE IF NOT EXISTS users(
                id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','prescripteur','laboratoire','chef_labo')),
                service TEXT, active INTEGER DEFAULT 0, approved INTEGER DEFAULT 0, created_at TEXT NOT NULL, suspended_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS requests(
                id SERIAL PRIMARY KEY, auto_number TEXT UNIQUE, sample_number TEXT, code_prelevement TEXT,
                date_prelevement TEXT, heure_prelevement TEXT, service_prescripteur TEXT, patient_status TEXT,
                age TEXT, age_unit TEXT, sex TEXT, patient_antibiotics TEXT, patient_probe TEXT, sample_type TEXT,
                patient_informe_decl TEXT, technique_maitrisee_decl TEXT, toilette_decl TEXT, flacon_sterile_decl TEXT,
                delai_miction_depot TEXT, temperature_conservation TEXT, prescriber_name TEXT, patient_name TEXT,
                patient_firstname TEXT, patient_phone TEXT, clinical_context TEXT, exam_requested TEXT, urgent TEXT,
                observations_prescripteur TEXT, created_by INTEGER NOT NULL, created_by_name TEXT, status TEXT NOT NULL,
                conformity TEXT DEFAULT 'Non évalué', rejection_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS lab_results(
                request_id INTEGER PRIMARY KEY, reception_date TEXT, reception_time TEXT, aspect TEXT, leucocytes TEXT,
                hematies TEXT, cellules_epitheliales TEXT, autres_micro TEXT, gram_result TEXT, culture_status TEXT,
                culture_details TEXT, antibiogram_json TEXT, conclusion TEXT, validator_name TEXT, validator_title TEXT,
                lab_operator_name TEXT, chief_validator_name TEXT, chief_validation_at TEXT, result_sent_at TEXT, quality_json TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS email_verifications(
                id SERIAL PRIMARY KEY, email TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0, created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS audit(id SERIAL PRIMARY KEY, user_id INTEGER, user_name TEXT, action TEXT, created_at TEXT NOT NULL)""",
        ]
    else:
        ddl = [
            """CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','prescripteur','laboratoire','chef_labo')),
                service TEXT, active INTEGER DEFAULT 0, approved INTEGER DEFAULT 0, created_at TEXT NOT NULL, suspended_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS requests(
                id INTEGER PRIMARY KEY AUTOINCREMENT, auto_number TEXT UNIQUE, sample_number TEXT, code_prelevement TEXT,
                date_prelevement TEXT, heure_prelevement TEXT, service_prescripteur TEXT, patient_status TEXT,
                age TEXT, age_unit TEXT, sex TEXT, patient_antibiotics TEXT, patient_probe TEXT, sample_type TEXT,
                patient_informe_decl TEXT, technique_maitrisee_decl TEXT, toilette_decl TEXT, flacon_sterile_decl TEXT,
                delai_miction_depot TEXT, temperature_conservation TEXT, prescriber_name TEXT, patient_name TEXT,
                patient_firstname TEXT, patient_phone TEXT, clinical_context TEXT, exam_requested TEXT, urgent TEXT,
                observations_prescripteur TEXT, created_by INTEGER NOT NULL, created_by_name TEXT, status TEXT NOT NULL,
                conformity TEXT DEFAULT 'Non évalué', rejection_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS lab_results(
                request_id INTEGER PRIMARY KEY, reception_date TEXT, reception_time TEXT, aspect TEXT, leucocytes TEXT,
                hematies TEXT, cellules_epitheliales TEXT, autres_micro TEXT, gram_result TEXT, culture_status TEXT,
                culture_details TEXT, antibiogram_json TEXT, conclusion TEXT, validator_name TEXT, validator_title TEXT,
                lab_operator_name TEXT, chief_validator_name TEXT, chief_validation_at TEXT, result_sent_at TEXT, quality_json TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS email_verifications(
                id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0, created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT, action TEXT, created_at TEXT NOT NULL)""",
        ]
    con = db()
    try:
        cur = con.cursor()
        for s in ddl:
            cur.execute(s)
        con.commit()
    finally:
        con.close()
    ensure_professional_tables()
    ensure_admin()


def ensure_professional_tables():
    if USE_PG:
        statements = [
            """CREATE TABLE IF NOT EXISTS non_conformities(
                id SERIAL PRIMARY KEY, request_id INTEGER, type_nc TEXT NOT NULL, description TEXT, severity TEXT, impact TEXT,
                consequence TEXT, decision_taken TEXT, declared_by INTEGER, declared_by_name TEXT, declared_at TEXT NOT NULL, status TEXT DEFAULT 'Ouverte'
            )""",
            """CREATE TABLE IF NOT EXISTS capa_actions(
                id SERIAL PRIMARY KEY, non_conformity_id INTEGER, corrective_action TEXT, preventive_action TEXT, responsible TEXT,
                due_date TEXT, status TEXT DEFAULT 'Ouverte', result TEXT, created_by INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS support_tickets(
                id SERIAL PRIMARY KEY, title TEXT NOT NULL, description TEXT, category TEXT, status TEXT DEFAULT 'Ouvert',
                created_by INTEGER, created_by_name TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""",
        ]
    else:
        statements = [
            """CREATE TABLE IF NOT EXISTS non_conformities(
                id INTEGER PRIMARY KEY AUTOINCREMENT, request_id INTEGER, type_nc TEXT NOT NULL, description TEXT, severity TEXT, impact TEXT,
                consequence TEXT, decision_taken TEXT, declared_by INTEGER, declared_by_name TEXT, declared_at TEXT NOT NULL, status TEXT DEFAULT 'Ouverte'
            )""",
            """CREATE TABLE IF NOT EXISTS capa_actions(
                id INTEGER PRIMARY KEY AUTOINCREMENT, non_conformity_id INTEGER, corrective_action TEXT, preventive_action TEXT, responsible TEXT,
                due_date TEXT, status TEXT DEFAULT 'Ouverte', result TEXT, created_by INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS support_tickets(
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT, category TEXT, status TEXT DEFAULT 'Ouvert',
                created_by INTEGER, created_by_name TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )""",
        ]
    for s in statements:
        execute(s)
    ensure_column("audit", "ip_address", "TEXT")

def ensure_column(table, col, ddl):
    try:
        execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    except Exception:
        pass

def ensure_admin():
    ensure_column("users", "approved", "INTEGER DEFAULT 0")
    ensure_column("users", "email_verified", "INTEGER DEFAULT 0")
    admin = execute("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,), fetchone=True)
    hp = hash_password(ADMIN_PASSWORD)
    if admin:
        execute("UPDATE users SET role='admin', active=1, approved=1, email_verified=1, password_hash=?, service='Administration' WHERE email=?", (hp, ADMIN_EMAIL))
    else:
        execute("INSERT INTO users(name,email,password_hash,role,service,active,approved,email_verified,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("Administrateur", ADMIN_EMAIL, hp, "admin", "Administration", 1, 1, 1, now()))
    execute("UPDATE users SET role='prescripteur', active=0, approved=0 WHERE role='admin' AND email<>?", (ADMIN_EMAIL,))

def audit(action):
    u = current_user()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "") if request else ""
    try:
        execute("INSERT INTO audit(user_id,user_name,action,created_at,ip_address) VALUES(?,?,?,?,?)", (u.get('id') if u else None, u.get('name') if u else '', action, now(), ip))
    except Exception:
        execute("INSERT INTO audit(user_id,user_name,action,created_at) VALUES(?,?,?,?)", (u.get('id') if u else None, u.get('name') if u else '', action, now()))

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return execute("SELECT * FROM users WHERE id=? AND active=1 AND approved=1", (uid,), fetchone=True)

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return redirect("/login")
            if u["role"] not in roles:
                return page("Accès interdit", "<div class='card'><h2>Accès interdit</h2></div>", u, 403)
            return fn(u, *a, **kw)
        return wrapper
    return deco

def formv(k):
    return request.form.get(k, "").strip()

def pill(s):
    cls = "ok" if s in ("Actif", "Validé et envoyé", "Conforme", "Approuvé") else ("bad" if s in ("Suspendu", "Rejeté", "Non conforme", "Supprimé", "En attente") else "wait")
    return f"<span class='pill {cls}'>{s}</span>"

def page(title, content, user=None, status=200):
    menu = ""
    if user:
        items = []
        if user["role"] == "admin":
            items = [("/admin/users", "Utilisateurs"), ("/admin/export", "Exports"), ("/admin/reset", "Réinitialisation"), ("/support", "Support"), ("/audit", "Journal")]
        elif user["role"] == "prescripteur":
            items = [("/request/new", "Nouvelle demande"), ("/requests", "Mes demandes"), ("/archive", "Archives"), ("/support", "Support")]
        elif user["role"] == "laboratoire":
            items = [("/lab/inbox", "Demandes reçues"), ("/lab/processed", "Analyses traitées"), ("/quality/dashboard", "Tableau qualité"), ("/quality/nonconformities", "Non-conformités"), ("/quality/capa", "CAPA"), ("/microbiology/resistance", "Antibiorésistance"), ("/support", "Support")]
        elif user["role"] == "chef_labo":
            items = [("/chief/pending", "À valider"), ("/chief/all", "Tous les bilans"), ("/quality/dashboard", "Tableau qualité"), ("/quality/nonconformities", "Non-conformités"), ("/quality/capa", "CAPA"), ("/microbiology/resistance", "Antibiorésistance"), ("/support", "Support")]
        menu = "".join(f"<a class='nav' href='{u}'>{t}</a>" for u, t in items) + "<a class='nav' href='/account/password'>Changer mot de passe</a><a class='nav danger' href='/logout'>Déconnexion</a>"
    html = f"""<!doctype html><html lang='fr'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title} - {APP_NAME}</title>
<style>
:root{{--blue:#075985;--blue2:#0284c7;--accent:#14b8a6;--bg:#eef7fb;--line:#dbe7f0;--ink:#0f172a;--mut:#64748b;--card:#ffffff;--shadow:0 18px 50px rgba(15,23,42,.10)}}
*{{box-sizing:border-box}}body{{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at top left,#e0f2fe,#f8fafc 42%,#eef2ff);color:var(--ink)}}
a{{color:inherit}}.shell{{display:grid;grid-template-columns:292px 1fr;min-height:100vh}}.side{{background:linear-gradient(180deg,#062b49,#073b62);color:#fff;padding:22px;position:sticky;top:0;height:100vh;box-shadow:12px 0 30px rgba(2,8,23,.15);overflow:auto}}.logo{{width:50px;height:50px;border-radius:17px;background:linear-gradient(135deg,#38bdf8,#14b8a6);display:grid;place-items:center;font-weight:1000;box-shadow:0 10px 25px rgba(20,184,166,.35)}}.brand{{display:flex;gap:12px;align-items:center;margin-bottom:24px}}.brand h1{{font-size:20px;margin:0;letter-spacing:.2px}}.brand p{{font-size:12px;color:#bfdbfe;margin:3px 0 0}}.nav{{display:flex;align-items:center;gap:10px;text-decoration:none;padding:12px 14px;border-radius:16px;margin:7px 0;color:#e0f2fe;font-weight:800;border:1px solid transparent}}.nav:hover{{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.16)}}.danger{{color:#fecaca}}.top{{background:rgba(255,255,255,.88);backdrop-filter:blur(12px);border-bottom:1px solid var(--line);padding:15px 24px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:4}}.top b{{font-size:18px}}.content{{padding:26px;max-width:1500px}}.card{{background:rgba(255,255,255,.96);border:1px solid #e2e8f0;border-radius:24px;box-shadow:var(--shadow);padding:22px;margin-bottom:20px}}.card h2,.card h3{{margin-top:0}}.grid{{display:grid;gap:14px}}.g2{{grid-template-columns:repeat(2,1fr)}}.g3{{grid-template-columns:repeat(3,1fr)}}.g4{{grid-template-columns:repeat(4,1fr)}}label{{font-size:13px;color:#475569;font-weight:800}}input,select,textarea{{width:100%;padding:12px 13px;border:1px solid #cbd5e1;border-radius:14px;background:#fbfdff;margin-top:6px;font-size:14px;outline:none}}input:focus,select:focus,textarea:focus{{border-color:#0284c7;box-shadow:0 0 0 4px rgba(2,132,199,.12)}}textarea{{min-height:86px}}.btn{{border:0;border-radius:14px;background:linear-gradient(135deg,#075985,#0284c7);color:white;padding:12px 16px;font-weight:900;cursor:pointer;text-decoration:none;display:inline-block;box-shadow:0 10px 22px rgba(2,132,199,.22)}}.btn:hover{{filter:brightness(1.04)}}.btn.sec{{background:#e2e8f0;color:#0f172a;box-shadow:none}}.btn.ok{{background:linear-gradient(135deg,#15803d,#16a34a)}}.btn.bad{{background:linear-gradient(135deg,#b91c1c,#ef4444)}}.msg{{padding:13px 15px;border-left:5px solid #0284c7;background:#eff6ff;border-radius:16px;color:#1e3a8a;margin:12px 0}}.table{{width:100%;border-collapse:separate;border-spacing:0;overflow:hidden;border-radius:16px}}.table th,.table td{{padding:12px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top}}.table th{{background:#f1f5f9;color:#475569;font-size:12px;text-transform:uppercase;letter-spacing:.35px}}.table tr:hover td{{background:#f8fafc}}.pill{{display:inline-block;border-radius:999px;padding:6px 11px;font-size:12px;font-weight:1000}}.pill.ok{{background:#dcfce7;color:#166534}}.pill.bad{{background:#fee2e2;color:#991b1b}}.pill.wait{{background:#fef3c7;color:#92400e}}.login{{max-width:590px;margin:7vh auto}}.auth-card{{border-top:6px solid #0284c7}}.small{{color:#64748b;font-size:12px}}.menu-toggle{{display:none;border:0;background:#e2e8f0;border-radius:12px;padding:10px 12px;font-weight:900}}.reportPage{{width:210mm;min-height:297mm;margin:0 auto;background:#fff;color:#000;padding:10mm;border:1px solid #111;font-family:Arial,sans-serif;font-size:11.2pt;line-height:1.25}}.reportPage h1{{font-size:16pt;text-align:center;margin:2mm 0;text-transform:uppercase}}.center{{text-align:center}}.row{{display:grid;grid-template-columns:1fr 1fr;gap:2mm 12mm;margin:2mm 0}}.box{{border:1px solid #111;padding:2.5mm;margin-top:3mm;min-height:16mm}}.boxTitle{{font-weight:900;text-align:center;border-bottom:1px solid #111;margin:-2.5mm -2.5mm 2mm -2.5mm;padding:1.5mm;text-transform:uppercase}}.abg{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:2mm}}.abg>div{{border:1px solid #333;min-height:26mm;padding:2mm}}.sign{{margin-top:8mm;text-align:right}}@media(max-width:900px){{.shell{{grid-template-columns:1fr}}.side{{height:auto;position:relative;display:none}}.side.open{{display:block}}.menu-toggle{{display:inline-block}}.g2,.g3,.g4{{grid-template-columns:1fr}}.content{{padding:14px}}.top{{padding:12px}}.reportPage{{width:100%;min-height:auto;padding:6mm;font-size:10pt}}}}@media print{{body{{background:#fff}}.side,.top,.noPrint,.card:not(.printCard){{display:none!important}}.shell{{display:block}}.content{{padding:0}}.reportPage{{border:0;margin:0;width:210mm;height:297mm;overflow:hidden}}}}
</style></head><body>"""
    if user:
        html += f"<div class='shell'><aside class='side' id='sideNav'><div class='brand'><div class='logo'>EC</div><div><h1>{APP_NAME}</h1><p>Plateforme ECBU</p></div></div>{menu}</aside><main><div class='top'><div><button class='menu-toggle' onclick=\"document.getElementById('sideNav').classList.toggle('open')\">☰ Menu</button> <b>{title}</b></div><span class='small'>{user['name']} — {user['role']}</span></div><div class='content'>{content}</div></main></div>"
    else:
        html += content
    html += "</body></html>"
    return Response(html, status=status, mimetype="text/html")

@app.route("/")
def home():
    u = current_user()
    if not u:
        return redirect("/login")
    return redirect({"admin":"/admin/users","prescripteur":"/requests","laboratoire":"/lab/inbox","chef_labo":"/chief/pending"}[u["role"]])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = formv("email").lower()
        pwd = formv("password")
        u = execute("SELECT * FROM users WHERE email=?", (email,), fetchone=True)
        if not u or not verify_password(u["password_hash"], pwd):
            return page("Connexion", "<div class='login card'><h1>Accès refusé</h1><a class='btn' href='/login'>Réessayer</a></div>", None, 401)
        if not u.get("approved") or not u.get("active"):
            return page("Compte en attente", "<div class='login card'><h1>Compte en attente</h1><p>Votre compte doit être validé par l’administrateur.</p><a class='btn' href='/login'>Retour</a></div>", None, 403)
        session["uid"] = u["id"]
        audit("Connexion")
        return redirect("/")
    return page("Connexion", """<div class='login card'><div class='logo' style='margin:auto'>EC</div><h1 class='center'>Connexion</h1><form method='post' class='grid'><label>Email<input name='email' type='email' required></label><label>Mot de passe<input name='password' type='password' required></label><button class='btn'>Connexion</button></form><p class='center'><a href='/register'>Créer un compte utilisateur</a></p></div>""")

@app.route("/register/request-code", methods=["GET", "POST"])
def request_email_code():
    if request.method == "GET":
        return page("Vérification email", """<div class='login card auth-card'><div class='logo' style='margin:auto'>EC</div><h1 class='center'>Vérification de l'adresse email</h1><form method='post' class='grid'><label>Adresse email professionnelle<input name='email' type='email' required></label><button class='btn ok'>Recevoir le code de vérification</button></form><p class='small center'>Le code est valable pendant 1 heure. Après vérification, le compte reste soumis à validation administrateur.</p></div>""")
    email = formv("email").lower()
    if not email or "@" not in email:
        return page("Vérification email", "<div class='login card'><h1>Email invalide</h1><a class='btn' href='/register'>Retour</a></div>", None, 400)
    if execute("SELECT id FROM users WHERE email=?", (email,), fetchone=True):
        return page("Vérification email", "<div class='login card'><h1>Email déjà utilisé</h1><p>Un compte existe déjà avec cette adresse.</p><a class='btn' href='/login'>Connexion</a></div>", None, 400)
    try:
        code = create_email_code(email)
        send_confirmation_email(email, code)
        return page("Code envoyé", f"<div class='login card'><h1>Code envoyé</h1><p>Un code de confirmation valable 1 heure a été envoyé à <b>{html.escape(email)}</b>.</p><a class='btn' href='/register?email={html.escape(email)}'>Continuer l’inscription</a></div>")
    except Exception as e:
        return page("Erreur email", f"<div class='login card'><h1>Envoi impossible</h1><p>Le serveur email n’est pas encore configuré ou l’envoi a échoué.</p><p class='small'>{html.escape(str(e))}</p><a class='btn' href='/register'>Retour</a></div>", None, 500)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        role = formv("role")
        if role == "admin" or role not in ("prescripteur", "laboratoire", "chef_labo"):
            role = "prescripteur"
        email = formv("email").lower()
        ok, msg = verify_email_code(email, formv("email_code"))
        if not ok:
            return page("Vérification échouée", f"<div class='login card'><h1>Code non valide</h1><p>{html.escape(msg)}</p><a class='btn' href='/register?email={html.escape(email)}'>Réessayer</a></div>", None, 400)
        try:
            execute("INSERT INTO users(name,email,password_hash,role,service,active,approved,email_verified,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (formv("name"), email, hash_password(formv("password")), role, formv("service"), 0, 0, 1, now()))
        except Exception:
            return page("Inscription", "<div class='login card'><h1>Email déjà utilisé</h1><a class='btn' href='/register'>Retour</a></div>", None, 400)
        audit("Compte utilisateur créé après vérification email")
        return page("Inscription reçue", "<div class='login card'><h1>Compte créé</h1><p>Votre email est vérifié. Votre accès sera disponible après validation par l’administrateur.</p><a class='btn' href='/login'>Connexion</a></div>")
    prefill = html.escape(request.args.get("email", ""))
    return page("Créer un compte", f"""
    <div class='login card auth-card'>
      <div class='logo' style='margin:auto'>EC</div>
      <h1 class='center'>Créer un compte sécurisé</h1>
      <div class='msg'>Étape 1 : demandez un code de vérification envoyé par email. Étape 2 : utilisez ce code pour soumettre votre compte. L’accès restera ensuite en attente de validation par l’administrateur.</div>
      <form method='post' action='/register/request-code' class='grid'>
        <label>Adresse email professionnelle<input name='email' type='email' value='{prefill}' required></label>
        <button class='btn sec'>Recevoir le code de vérification</button>
      </form>
      <hr style='border:0;border-top:1px solid #e2e8f0;margin:18px 0'>
      <form method='post' class='grid'>
        <label>Nom complet<input name='name' required></label>
        <label>Email vérifié<input name='email' type='email' value='{prefill}' required></label>
        <label>Code reçu par email<input name='email_code' inputmode='numeric' minlength='6' maxlength='6' required></label>
        <label>Mot de passe<input name='password' type='password' minlength='8' required></label>
        <label>Rôle<select name='role'><option value='prescripteur'>Clinicien prescripteur</option><option value='laboratoire'>Technicien laboratoire</option><option value='chef_labo'>Chef service laboratoire</option></select></label>
        <label>Service<input name='service' required></label>
        <button class='btn'>Soumettre le compte</button>
      </form>
    </div>""")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/account/password", methods=["GET", "POST"])
def change_password():
    u = current_user()
    if not u:
        return redirect("/login")
    if request.method == "POST":
        current = formv("current_password")
        new1 = formv("new_password")
        new2 = formv("confirm_password")
        fresh = execute("SELECT * FROM users WHERE id=?", (u["id"],), fetchone=True)
        if not fresh or not verify_password(fresh["password_hash"], current):
            return page("Changer mot de passe", "<div class='card'><h2>Mot de passe actuel incorrect</h2><a class='btn' href='/account/password'>Réessayer</a></div>", u, 400)
        if new1 != new2:
            return page("Changer mot de passe", "<div class='card'><h2>Les deux nouveaux mots de passe ne sont pas identiques</h2><a class='btn' href='/account/password'>Réessayer</a></div>", u, 400)
        if len(new1) < 10 or not any(c.isdigit() for c in new1) or not any(c.isupper() for c in new1) or not any(c.islower() for c in new1):
            return page("Changer mot de passe", "<div class='card'><h2>Mot de passe insuffisant</h2><p>Utilisez au moins 10 caractères avec majuscule, minuscule et chiffre.</p><a class='btn' href='/account/password'>Réessayer</a></div>", u, 400)
        if verify_password(fresh["password_hash"], new1):
            return page("Changer mot de passe", "<div class='card'><h2>Le nouveau mot de passe doit être différent de l’ancien</h2><a class='btn' href='/account/password'>Réessayer</a></div>", u, 400)
        execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new1), u["id"]))
        audit("Changement de mot de passe")
        session.clear()
        return page("Mot de passe modifié", "<div class='login card'><h1>Mot de passe modifié</h1><p>Reconnectez-vous avec le nouveau mot de passe.</p><a class='btn' href='/login'>Connexion</a></div>")
    return page("Changer mot de passe", """<div class='card'><h2>Changer le mot de passe</h2><form method='post' class='grid g2'><label>Mot de passe actuel<input name='current_password' type='password' autocomplete='current-password' required></label><label>Nouveau mot de passe<input name='new_password' type='password' autocomplete='new-password' minlength='10' required></label><label>Confirmer le nouveau mot de passe<input name='confirm_password' type='password' autocomplete='new-password' minlength='10' required></label><div><br><button class='btn ok'>Enregistrer</button></div></form><p class='small'>Exigence : au moins 10 caractères avec majuscule, minuscule et chiffre.</p></div>""", u)

@app.route("/admin/users")
@role_required("admin")
def admin_users(u):
    users = execute("SELECT * FROM users ORDER BY approved, role, name", fetch=True)
    trs = ""
    for x in users:
        status = "Approuvé" if x.get("approved") and x.get("active") else ("Suspendu" if x.get("approved") else "En attente")
        verified = "Oui" if x.get("email_verified") else "Non"
        action = ""
        if x["email"] != ADMIN_EMAIL:
            if x.get("email_verified"):
                action = f"""<form method='post' action='/admin/user-action' style='display:inline'><input type='hidden' name='id' value='{x['id']}'><button class='btn ok' name='action' value='approve'>Valider</button> <button class='btn sec' name='action' value='toggle'>Suspendre/Réactiver</button> <button class='btn bad' name='action' value='delete'>Supprimer</button></form>"""
            else:
                action = "<span class='small'>Validation impossible : email non vérifié</span>"
        trs += f"<tr><td>{x['name']}</td><td>{x['email']}</td><td>{verified}</td><td>{x['role']}</td><td>{x.get('service','')}</td><td>{pill(status)}</td><td>{action}</td></tr>"
    return page("Utilisateurs", f"<div class='card'><h2>Gestion des comptes</h2><p class='small'>Un compte ne peut être validé qu’après confirmation de son email par code unique valable 1 heure.</p><table class='table'><tr><th>Nom</th><th>Email</th><th>Email vérifié</th><th>Rôle</th><th>Service</th><th>Statut</th><th>Action</th></tr>{trs}</table></div>", u)

@app.route("/admin/user-action", methods=["POST"])
@role_required("admin")
def user_action(u):
    uid, act = formv("id"), formv("action")
    target = execute("SELECT * FROM users WHERE id=?", (uid,), fetchone=True)
    if target and target["email"] != ADMIN_EMAIL:
        if act == "approve":
            if not target.get("email_verified"):
                return page("Validation impossible", "<div class='card'><h2>Email non vérifié</h2><p>Ce compte doit confirmer son email avant validation administrateur.</p><a class='btn' href='/admin/users'>Retour</a></div>", u, 403)
            execute("UPDATE users SET approved=1, active=1, suspended_at=NULL WHERE id=?", (uid,))
        elif act == "toggle":
            new = 0 if target.get("active") else 1
            execute("UPDATE users SET active=?, approved=1, suspended_at=? WHERE id=?", (new, now() if not new else None, uid))
        elif act == "delete":
            execute("DELETE FROM users WHERE id=?", (uid,))
    return redirect("/admin/users")

@app.route("/request/new", methods=["GET", "POST"])
@role_required("prescripteur")
def new_request(u):
    if request.method == "POST":
        count = execute("SELECT COUNT(*) AS n FROM requests", fetchone=True)["n"] + 1
        auto = f"DEM-{dt.datetime.now().year}-{count:05d}"
        fields = ["code_prelevement","date_prelevement","heure_prelevement","service_prescripteur","patient_status","age","age_unit","sex","patient_antibiotics","patient_probe","sample_type","patient_informe_decl","technique_maitrisee_decl","toilette_decl","flacon_sterile_decl","delai_miction_depot","temperature_conservation","prescriber_name","patient_name","patient_firstname","patient_phone","clinical_context","exam_requested","urgent","observations_prescripteur"]
        vals = [formv(k) for k in fields]
        execute("""INSERT INTO requests(auto_number, sample_number, code_prelevement, date_prelevement, heure_prelevement, service_prescripteur, patient_status, age, age_unit, sex, patient_antibiotics, patient_probe, sample_type, patient_informe_decl, technique_maitrisee_decl, toilette_decl, flacon_sterile_decl, delai_miction_depot, temperature_conservation, prescriber_name, patient_name, patient_firstname, patient_phone, clinical_context, exam_requested, urgent, observations_prescripteur, created_by, created_by_name, status, conformity, rejection_reason, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (auto, "", *vals, u["id"], u["name"], "Envoyé au laboratoire", "Non évalué", "", now(), now()))
        return redirect("/requests")
    return page("Nouvelle demande", f"""<div class='card'><h2>Fiche de demande ECBU</h2><form method='post' class='grid g3'><label>Code prélèvement<input name='code_prelevement'></label><label>Date prélèvement<input type='date' name='date_prelevement' required></label><label>Heure prélèvement<input type='time' name='heure_prelevement' required></label><label>Nom patient<input name='patient_name' required></label><label>Prénoms patient<input name='patient_firstname' required></label><label>Contact<input name='patient_phone'></label><label>Âge<input name='age' required></label><label>Unité<select name='age_unit'><option>Ans</option><option>Mois</option><option>Jours</option></select></label><label>Sexe<select name='sex'><option>Masculin</option><option>Féminin</option></select></label><label>Service<input name='service_prescripteur' value='{u.get('service','')}' required></label><label>Médecin<input name='prescriber_name' value='{u['name']}' required></label><label>Statut patient<select name='patient_status'><option>Hospitalisé</option><option>Externe</option><option>Ambulatoire</option></select></label><label>Examen<select name='exam_requested'><option>ECBU</option><option>Culture urine + antibiogramme si positif</option></select></label><label>Urgent<select name='urgent'><option>Non</option><option>Oui</option></select></label><label>Antibiotiques<select name='patient_antibiotics'><option>Non</option><option>Oui</option><option>Non renseigné</option></select></label><label>Sonde urinaire<select name='patient_probe'><option>Non</option><option>Oui</option></select></label><label>Type prélèvement<select name='sample_type'><option>Jet moyen</option><option>Sonde urinaire</option><option>Poche collectrice</option><option>Autre</option></select></label><label>Délai<select name='delai_miction_depot'><option>≤ 2 h</option><option>2–4 h</option><option>> 4 h</option><option>Non renseigné</option></select></label><label>Conservation<select name='temperature_conservation'><option>Réfrigération</option><option>Ambiante</option><option>Non renseignée</option></select></label><label>Patient informé<select name='patient_informe_decl'><option>Oui</option><option>Non</option></select></label><label>Technique maîtrisée<select name='technique_maitrisee_decl'><option>Oui</option><option>Non</option></select></label><label>Toilette intime<select name='toilette_decl'><option>Oui</option><option>Non</option></select></label><label>Flacon stérile<select name='flacon_sterile_decl'><option>Oui</option><option>Non</option></select></label><label style='grid-column:1/-1'>Contexte clinique<textarea name='clinical_context'></textarea></label><label style='grid-column:1/-1'>Observations<textarea name='observations_prescripteur'></textarea></label><button class='btn ok'>Envoyer</button></form></div>""", u)


def request_table(u, rows_, title, lab=False, chief=False):
    trs = ""
    for r in rows_:
        actions = f"<a class='btn sec' href='/report?id={r['id']}'>Bon</a> "
        if lab:
            actions += f"<a class='btn' href='/lab/edit?id={r['id']}'>Traiter</a> "
            if r.get('status') in ('Envoyé au laboratoire','En cours laboratoire','En attente validation chef','Rejeté'):
                actions += f"<form method='post' action='/lab/delete' style='display:inline' onsubmit=\"return confirm('Supprimer cette demande des listes du laboratoire ?');\"><input type='hidden' name='id' value='{r['id']}'><button class='btn bad'>Supprimer</button></form> "
            if r.get('status') == 'En attente validation chef':
                actions += f"<form method='post' action='/lab/send-direct' style='display:inline' onsubmit=\"return confirm('Envoyer directement ce résultat au prescripteur sans validation chef ?');\"><input type='hidden' name='id' value='{r['id']}'><button class='btn ok'>Envoyer direct</button></form>"
        if chief:
            actions += f"<a class='btn sec' href='/lab/edit?id={r['id']}'>Corriger</a> "
            if r.get('status') == "En attente validation chef":
                actions += f"<form method='post' action='/chief/validate' style='display:inline'><input type='hidden' name='id' value='{r['id']}'><button class='btn ok'>Valider</button></form>"
        trs += f"<tr><td>{r['auto_number']}</td><td>{r.get('sample_number') or 'À attribuer'}</td><td>{r['service_prescripteur']}</td><td>{r['patient_name']} {r['patient_firstname']}</td><td>{pill(r['status'])}</td><td>{pill(r['conformity'])}</td><td>{actions}</td></tr>"
    return page(title, f"<div class='card'><h2>{title}</h2><table class='table'><tr><th>N° demande</th><th>N° échantillon</th><th>Service</th><th>Patient</th><th>Statut</th><th>Conformité</th><th>Action</th></tr>{trs or '<tr><td colspan=7>Aucune donnée.</td></tr>'}</table></div>", u)

@app.route("/requests")
@app.route("/archive")
@role_required("prescripteur")
def requests_page(u):
    rows_ = execute("SELECT * FROM requests WHERE created_by=? AND status!='Supprimé' ORDER BY id DESC", (u["id"],), fetch=True)
    return request_table(u, rows_, "Mes demandes")

@app.route("/lab/inbox")
@role_required("laboratoire")
def lab_inbox(u):
    rows_ = execute("SELECT * FROM requests WHERE status IN ('Envoyé au laboratoire','En cours laboratoire','Rejeté') ORDER BY id DESC", fetch=True)
    return request_table(u, rows_, "Demandes reçues", lab=True)

@app.route("/lab/processed")
@role_required("laboratoire","chef_labo")
def lab_processed(u):
    rows_ = execute("SELECT * FROM requests WHERE status IN ('En attente validation chef','Validé et envoyé','Rejeté') ORDER BY id DESC", fetch=True)
    return request_table(u, rows_, "Archives laboratoire", lab=(u["role"]=="laboratoire"), chief=(u["role"]=="chef_labo"))


@app.route("/lab/edit", methods=["GET","POST"])
@role_required("laboratoire", "chef_labo")
def lab_edit(u):
    rid = request.values.get("id", "")
    r = execute("SELECT * FROM requests WHERE id=?", (rid,), fetchone=True)
    if not r:
        return redirect("/lab/inbox" if u["role"] == "laboratoire" else "/chief/pending")
    lab = execute("SELECT * FROM lab_results WHERE request_id=?", (rid,), fetchone=True) or {}
    if request.method == "POST":
        quality = [k for k,_ in RULES if request.form.get(k) == "on"]
        conformity = "Conforme" if len(quality) == len(RULES) else "Non conforme"
        atbs = []
        for i,a in enumerate(ANTIBIOTICS):
            atbs.append({"name": a, "diam": formv(f"diam_{i}"), "interp": formv(f"interp_{i}"), "show": formv(f"show_{i}") == "Oui"})
        direct = formv("direct_send") == "1"
        status = "Validé et envoyé" if direct else "En attente validation chef"
        execute("UPDATE requests SET sample_number=?, status=?, conformity=?, updated_at=? WHERE id=?", (formv("sample_number"), status, conformity, now(), rid))
        old = execute("SELECT request_id FROM lab_results WHERE request_id=?", (rid,), fetchone=True)
        vals = (rid, formv("reception_date"), formv("reception_time"), formv("aspect"), formv("leucocytes"), formv("hematies"), formv("cellules_epitheliales"), formv("autres_micro"), formv("gram_result"), formv("culture_status"), formv("culture_details"), json.dumps(atbs, ensure_ascii=False), formv("conclusion"), formv("validator_name"), formv("validator_title"), u["name"], json.dumps(quality, ensure_ascii=False))
        if old:
            execute("""UPDATE lab_results SET reception_date=?, reception_time=?, aspect=?, leucocytes=?, hematies=?, cellules_epitheliales=?, autres_micro=?, gram_result=?, culture_status=?, culture_details=?, antibiogram_json=?, conclusion=?, validator_name=?, validator_title=?, lab_operator_name=?, quality_json=? WHERE request_id=?""", vals[1:] + (rid,))
        else:
            execute("""INSERT INTO lab_results(request_id,reception_date,reception_time,aspect,leucocytes,hematies,cellules_epitheliales,autres_micro,gram_result,culture_status,culture_details,antibiogram_json,conclusion,validator_name,validator_title,lab_operator_name,quality_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", vals)
        if direct:
            execute("UPDATE lab_results SET chief_validator_name=?, chief_validation_at=?, result_sent_at=? WHERE request_id=?", (u["name"] + " (envoi direct laboratoire)", now(), now(), rid))
            audit("Envoi direct résultat au prescripteur")
        else:
            audit("Enregistrement/correction résultat laboratoire")
        return redirect("/lab/processed" if u["role"] == "laboratoire" else "/chief/pending")
    saved_quality = set()
    try:
        saved_quality = set(json.loads(lab.get('quality_json') or '[]'))
    except Exception:
        saved_quality = set()
    checks = "".join(f"<label><input type='checkbox' name='{k}' {'checked' if k in saved_quality else ''}> {v}</label>" for k,v in RULES)
    saved_atb = {}
    try:
        for a in json.loads(lab.get('antibiogram_json') or '[]'):
            saved_atb[a.get('name')] = a
    except Exception:
        saved_atb = {}
    atb_rows = ""
    for i,a in enumerate(ANTIBIOTICS):
        olda = saved_atb.get(a, {})
        interp = olda.get('interp', 'ND')
        show = 'Oui' if olda.get('show') else 'Non'
        atb_rows += f"<tr><td>{a}</td><td><input name='diam_{i}' value='{html.escape(str(olda.get('diam','')))}'></td><td><select name='interp_{i}'><option {'selected' if interp=='ND' else ''}>ND</option><option {'selected' if interp=='S' else ''}>S</option><option {'selected' if interp=='I' else ''}>I</option><option {'selected' if interp=='R' else ''}>R</option></select></td><td><select name='show_{i}'><option {'selected' if show=='Non' else ''}>Non</option><option {'selected' if show=='Oui' else ''}>Oui</option></select></td></tr>"
    culture_options = ''.join(f"<option {'selected' if (lab.get('culture_status') or '')==x else ''}>{x}</option>" for x in ['Positive','Négative','Contaminée','Rejetée'])
    role_note = "Le chef laboratoire peut corriger avant validation finale." if u["role"] == "chef_labo" else "Le laboratoire peut envoyer au chef ou envoyer directement si le chef est absent."
    return page("Traitement laboratoire", f"""<div class='card'><h2>Traitement — {r['auto_number']}</h2><div class='msg'>{role_note}</div><form method='post'><input type='hidden' name='id' value='{rid}'><div class='grid g3'><label>N° d’échantillon<input name='sample_number' value='{html.escape(str(r.get('sample_number') or ''))}' required></label><label>Date réception<input type='date' name='reception_date' value='{html.escape(str(lab.get('reception_date') or ''))}' required></label><label>Heure réception<input type='time' name='reception_time' value='{html.escape(str(lab.get('reception_time') or ''))}' required></label></div><h3>Conformité</h3><div class='grid g3'>{checks}</div><h3>Résultats</h3><div class='grid g3'><label>Aspect<input name='aspect' value='{html.escape(str(lab.get('aspect') or ''))}'></label><label>Leucocytes GB/ml<input name='leucocytes' value='{html.escape(str(lab.get('leucocytes') or ''))}'></label><label>Hématies GR/ml<input name='hematies' value='{html.escape(str(lab.get('hematies') or ''))}'></label><label>Cellules épithéliales<input name='cellules_epitheliales' value='{html.escape(str(lab.get('cellules_epitheliales') or ''))}'></label><label>Autres<input name='autres_micro' value='{html.escape(str(lab.get('autres_micro') or ''))}'></label><label>Culture<select name='culture_status'>{culture_options}</select></label><label style='grid-column:1/-1'>Coloration de Gram<textarea name='gram_result'>{html.escape(str(lab.get('gram_result') or ''))}</textarea></label><label style='grid-column:1/-1'>Culture / germe<textarea name='culture_details'>{html.escape(str(lab.get('culture_details') or ''))}</textarea></label><label style='grid-column:1/-1'>Conclusion<textarea name='conclusion'>{html.escape(str(lab.get('conclusion') or ''))}</textarea></label><label>Validateur proposé<input name='validator_name' value='{html.escape(str(lab.get('validator_name') or ''))}'></label><label>Titre validateur<input name='validator_title' value='{html.escape(str(lab.get('validator_title') or 'Biologiste médical'))}'></label></div><h3>Antibiogramme EUCAST</h3><table class='table'><tr><th>Antibiotique</th><th>Diamètre</th><th>S/I/R</th><th>Afficher</th></tr>{atb_rows}</table><br><button class='btn ok'>Enregistrer et envoyer au chef</button> <button class='btn bad' name='direct_send' value='1' onclick=\"return confirm('Confirmer l’envoi direct au prescripteur ?');\">Enregistrer et envoyer direct</button></form><form method='post' action='/lab/reject' style='margin-top:12px'><input type='hidden' name='id' value='{rid}'><label>Motif de rejet<textarea name='reason' required></textarea></label><button class='btn bad'>Rejeter</button></form></div>""", u)


@app.route("/lab/delete", methods=["POST"])
@role_required("laboratoire")
def lab_delete(u):
    rid = formv("id")
    execute("UPDATE requests SET status='Supprimé', updated_at=? WHERE id=? AND status!='Validé et envoyé'", (now(), rid))
    audit("Suppression logique demande par laboratoire")
    return redirect("/lab/inbox")

@app.route("/lab/send-direct", methods=["POST"])
@role_required("laboratoire")
def lab_send_direct(u):
    rid = formv("id")
    execute("UPDATE requests SET status='Validé et envoyé', updated_at=? WHERE id=? AND status='En attente validation chef'", (now(), rid))
    execute("UPDATE lab_results SET chief_validator_name=?, chief_validation_at=?, result_sent_at=? WHERE request_id=?", (u["name"] + " (envoi direct laboratoire)", now(), now(), rid))
    audit("Envoi direct résultat par laboratoire")
    return redirect("/lab/processed")

@app.route("/lab/reject", methods=["POST"])
@role_required("laboratoire")
def lab_reject(u):
    execute("UPDATE requests SET status='Rejeté', conformity='Non conforme', rejection_reason=?, updated_at=? WHERE id=?", (formv("reason"), now(), formv("id")))
    return redirect("/lab/inbox")

@app.route("/chief/pending")
@role_required("chef_labo")
def chief_pending(u):
    rows_ = execute("SELECT * FROM requests WHERE status='En attente validation chef' ORDER BY id DESC", fetch=True)
    return request_table(u, rows_, "Résultats à valider", chief=True)

@app.route("/chief/all")
@role_required("chef_labo")
def chief_all(u):
    rows_ = execute("SELECT * FROM requests WHERE status!='Supprimé' ORDER BY id DESC", fetch=True)
    return request_table(u, rows_, "Tous les bilans", chief=True)

@app.route("/chief/validate", methods=["POST"])
@role_required("chef_labo")
def chief_validate(u):
    rid = formv("id")
    execute("UPDATE requests SET status='Validé et envoyé', updated_at=? WHERE id=?", (now(), rid))
    execute("UPDATE lab_results SET chief_validator_name=?, chief_validation_at=?, result_sent_at=? WHERE request_id=?", (u["name"], now(), now(), rid))
    return redirect("/chief/pending")


@app.route("/report")
def report():
    u = current_user()
    if not u:
        return redirect("/login")
    rid = request.args.get("id", "")
    r = execute("SELECT * FROM requests WHERE id=?", (rid,), fetchone=True)
    l = execute("SELECT * FROM lab_results WHERE request_id=?", (rid,), fetchone=True) or {}
    if not r:
        abort(404)
    if u["role"] == "admin":
        return page("Accès interdit", "<div class='card'>Données médicales non accessibles à l’administrateur.</div>", u, 403)
    if r.get("status") == "Rejeté" or l.get("culture_status") == "Rejetée":
        return page("Bon indisponible", "<div class='card'><h2>Bon indisponible</h2><p>Ce prélèvement a été rejeté. Aucun bon ne peut être généré.</p></div>", u, 403)
    if u["role"] == "prescripteur":
        if r["created_by"] != u["id"]:
            return page("Accès interdit", "<div class='card'>Ce résultat appartient à un autre prescripteur.</div>", u, 403)
        if r.get("status") != "Validé et envoyé":
            return page("Résultat non disponible", "<div class='card'><h2>Résultat non encore disponible</h2><p>Le résultat sera visible après validation et envoi par le laboratoire.</p></div>", u, 403)
    def safe(v):
        return html.escape(str(v or ""), quote=True)
    culture = str(l.get("culture_status") or "").strip()
    culture_details = safe(l.get("culture_details"))
    if culture == "Positive":
        culture_block = f"<b>Culture :</b> Positive<br><b>Germe isolé / détails :</b><br>{culture_details or '—'}"
    elif culture == "Négative":
        culture_block = "<b>Culture :</b> Négative<br>Absence de croissance bactérienne significative."
    elif culture == "Contaminée":
        culture_block = "<b>Culture :</b> Contaminée<br>Culture contaminée : interprétation non fiable."
    else:
        culture_block = f"<b>Culture :</b> {safe(culture) or 'Non renseignée'}<br>{culture_details}"
    if culture == "Positive":
        groups = {"S": [], "I": [], "R": []}
        try:
            antibiogram_data = json.loads(l.get("antibiogram_json") or "[]")
        except Exception:
            antibiogram_data = []
        for a in antibiogram_data:
            if a.get("show") and a.get("interp") in groups:
                label = safe(a.get("name")) + (f" ({safe(a.get('diam'))} mm)" if a.get("diam") else "")
                groups[a.get("interp")].append(label)
        atb = f"<div class='abg'><div><b>Sensibles</b><br>{'<br>'.join(groups['S']) or '—'}</div><div><b>Intermédiaires</b><br>{'<br>'.join(groups['I']) or '—'}</div><div><b>Résistants</b><br>{'<br>'.join(groups['R']) or '—'}</div></div><div class='small'>S = Sensible ; I = Intermédiaire ; R = Résistant</div>"
    else:
        atb = "<b>Antibiogramme : Non applicable</b>"
    validateur = safe(l.get("validator_name") or l.get("chief_validator_name") or "")
    titre = safe(l.get("validator_title") or "Biologiste médical")
    validation_date = safe(l.get("chief_validation_at") or l.get("result_sent_at") or "")
    content = f"""
    <div class='card printCard'><div class='reportPage'>
      <div class='center'><b>LABORATOIRE DE BIOLOGIE MÉDICALE</b><br>Hôpital Saint Jean de Dieu de Boko</div>
      <h1>RÉSULTATS D’EXAMENS BIOLOGIQUES</h1>
      <h1 style='font-size:13pt;color:#075985'>EXAMEN CYTOBACTÉRIOLOGIQUE DES URINES (ECBU)</h1>
      <div class='row'>
        <div>Nom et prénom : <b>{safe(r.get('patient_name'))} {safe(r.get('patient_firstname'))}</b></div><div>N° d’échantillon : <b>{safe(r.get('sample_number'))}</b></div>
        <div>Sexe / Âge : {safe(r.get('sex'))} / {safe(r.get('age'))} {safe(r.get('age_unit'))}</div><div>Date du prélèvement : {safe(r.get('date_prelevement'))} {safe(r.get('heure_prelevement'))}</div>
        <div>Médecin prescripteur : {safe(r.get('prescriber_name'))}</div><div>Service de provenance : {safe(r.get('service_prescripteur'))}</div>
        <div>Nature du prélèvement : Urine</div><div>Statut du résultat : Validé</div>
      </div>
      <div class='box'><div class='boxTitle'>EXAMEN MACROSCOPIQUE</div>Aspect : {safe(l.get('aspect'))}</div>
      <div class='box'><div class='boxTitle'>EXAMEN MICROSCOPIQUE</div>Leucocytes : {safe(l.get('leucocytes'))} GB/ml<br>Hématies : {safe(l.get('hematies'))} GR/ml<br>Cellules épithéliales : {safe(l.get('cellules_epitheliales'))}<br>Autres : {safe(l.get('autres_micro'))}</div>
      <div class='box'><div class='boxTitle'>COLORATION DE GRAM</div>Résultat :<br>{safe(l.get('gram_result'))}</div>
      <div class='box'><div class='boxTitle'>CULTURE</div>{culture_block}</div>
      <div class='box'><div class='boxTitle'>ANTIBIOGRAMME (EUCAST)</div>{atb}</div>
      <div class='box'><div class='boxTitle'>CONCLUSION</div>{safe(l.get('conclusion'))}</div>
      <div class='sign'><b>VALIDATION</b><br>{validateur}<br>{titre}<br>{validation_date}</div>
    </div><div class='noPrint center' style='margin-top:14px'><button class='btn' onclick='print()'>Imprimer / PDF</button></div></div>"""
    return page("Bon de résultat", content, u)

@app.route("/admin/export")
@role_required("admin")
def admin_export(u):
    return page("Exports", "<div class='card'><h2>Exports</h2><a class='btn' href='/export/requests.csv'>Télécharger base demandes CSV</a></div>", u)

@app.route("/export/requests.csv")
@role_required("admin", "chef_labo")
def export_requests(u):
    data = execute("SELECT auto_number,sample_number,service_prescripteur,status,conformity,created_at,updated_at FROM requests ORDER BY id DESC", fetch=True)
    out = io.StringIO(); w = csv.writer(out, delimiter=';')
    w.writerow(['N° demande','N° échantillon','Service','Statut','Conformité','Création','Mise à jour'])
    for r in data:
        w.writerow([r['auto_number'], r.get('sample_number',''), r['service_prescripteur'], r['status'], r['conformity'], r['created_at'], r['updated_at']])
    return Response(out.getvalue().encode('utf-8-sig'), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=base_demandes_ecbu.csv'})


@app.route("/admin/reset", methods=["GET", "POST"])
@role_required("admin")
def admin_reset(u):
    if request.method == "POST":
        pwd = formv("password")
        confirm = formv("confirm")
        fresh = execute("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,), fetchone=True)
        if confirm != "REINITIALISER" or not fresh or not verify_password(fresh["password_hash"], pwd):
            return page("Réinitialisation refusée", "<div class='card'><h2>Confirmation incorrecte</h2><p>Mot de passe ou mot de confirmation invalide.</p><a class='btn' href='/admin/reset'>Retour</a></div>", u, 403)
        tables = ["lab_results", "requests", "non_conformities", "capa_actions", "support_tickets", "email_verifications", "audit"]
        if USE_PG:
            execute("TRUNCATE TABLE " + ", ".join(tables) + " RESTART IDENTITY CASCADE")
        else:
            for t in tables:
                execute(f"DELETE FROM {t}")
            try:
                execute("DELETE FROM sqlite_sequence WHERE name IN ('lab_results','requests','non_conformities','capa_actions','support_tickets','email_verifications','audit')")
            except Exception:
                pass
        audit("Réinitialisation complète des données métier par administrateur")
        return page("Réinitialisation terminée", "<div class='card'><h2>Données remises à zéro</h2><p>Les analyses, demandes, non-conformités, CAPA, tickets et journaux ont été remis à zéro. Les comptes utilisateurs sont conservés.</p><a class='btn' href='/admin/users'>Retour administration</a></div>", u)
    return page("Réinitialisation", """<div class='card'><h2>Réinitialisation des données métier</h2><div class='msg'>Action réservée à l’administrateur. Les comptes utilisateurs sont conservés. Les analyses, demandes, résultats, non-conformités, CAPA, tickets et journaux sont remis à zéro.</div><form method='post' class='grid g2'><label>Mot de passe administrateur<input name='password' type='password' required></label><label>Écrire exactement REINITIALISER<input name='confirm' required></label><div><button class='btn bad'>Réinitialiser</button></div></form></div>""", u)

@app.route("/support", methods=["GET", "POST"])
def support_center():
    u = current_user()
    if not u:
        return redirect("/login")
    if request.method == "POST":
        execute("""INSERT INTO support_tickets(title,description,category,status,created_by,created_by_name,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)""", (formv("title"), formv("description"), formv("category"), "Ouvert", u["id"], u["name"], now(), now()))
        audit("Création ticket support")
        return redirect("/support")
    if u["role"] == "admin":
        tickets = execute("SELECT * FROM support_tickets ORDER BY id DESC LIMIT 300", fetch=True)
    else:
        tickets = execute("SELECT * FROM support_tickets WHERE created_by=? ORDER BY id DESC LIMIT 300", (u["id"],), fetch=True)
    trs = "".join(f"<tr><td>{t['created_at']}</td><td>{t['category']}</td><td>{t['title']}</td><td>{t['status']}</td><td>{t.get('created_by_name','')}</td></tr>" for t in tickets) or "<tr><td colspan='5'>Aucun ticket.</td></tr>"
    content = f"""<div class='card'><h2>Signalement et assistance</h2><form method='post' class='grid g2'><label>Catégorie<select name='category'><option>Incident</option><option>Erreur</option><option>Assistance</option><option>Suggestion</option></select></label><label>Titre<input name='title' required></label><label style='grid-column:1/-1'>Description<textarea name='description' required></textarea></label><button class='btn ok'>Envoyer</button></form></div><div class='card'><h2>Tickets</h2><table class='table'><tr><th>Date</th><th>Catégorie</th><th>Titre</th><th>Statut</th><th>Demandeur</th></tr>{trs}</table></div>"""
    return page("Support", content, u)

@app.route("/quality/dashboard")
@role_required("laboratoire", "chef_labo")
def quality_dashboard(u):
    total = execute("SELECT COUNT(*) AS n FROM requests WHERE status!='Supprimé'", fetchone=True)["n"]
    conformes = execute("SELECT COUNT(*) AS n FROM requests WHERE conformity='Conforme' AND status!='Supprimé'", fetchone=True)["n"]
    nonconf = execute("SELECT COUNT(*) AS n FROM requests WHERE conformity='Non conforme' AND status!='Supprimé'", fetchone=True)["n"]
    rejetes = execute("SELECT COUNT(*) AS n FROM requests WHERE status='Rejeté'", fetchone=True)["n"]
    analyses = execute("SELECT COUNT(*) AS n FROM requests WHERE status='Validé et envoyé'", fetchone=True)["n"]
    nc_rows = execute("SELECT type_nc, COUNT(*) AS n FROM non_conformities GROUP BY type_nc ORDER BY n DESC", fetch=True)
    taux_conf = round(conformes*100/total,1) if total else 0
    taux_nc = round(nonconf*100/total,1) if total else 0
    nc_table = "".join(f"<tr><td>{r['type_nc']}</td><td>{r['n']}</td></tr>" for r in nc_rows) or "<tr><td colspan='2'>Aucune non-conformité.</td></tr>"
    content = f"""<div class='grid g4'><div class='card'><h3>Demandes</h3><h1>{total}</h1></div><div class='card'><h3>Analyses validées</h3><h1>{analyses}</h1></div><div class='card'><h3>Conformité</h3><h1>{taux_conf}%</h1></div><div class='card'><h3>Non-conformité</h3><h1>{taux_nc}%</h1></div></div><div class='card'><h2>Non-conformités par type</h2><table class='table'><tr><th>Type</th><th>Nombre</th></tr>{nc_table}</table></div><div class='card'><h2>Exports scientifiques</h2><a class='btn' href='/export/requests.csv'>Demandes CSV</a> <a class='btn sec' href='/quality/export/nonconformities.csv'>Non-conformités CSV</a></div>"""
    return page("Tableau qualité", content, u)

@app.route("/quality/nonconformities", methods=["GET", "POST"])
@role_required("laboratoire", "chef_labo")
def nonconformities(u):
    if request.method == "POST":
        execute("""INSERT INTO non_conformities(request_id,type_nc,description,severity,impact,consequence,decision_taken,declared_by,declared_by_name,declared_at,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (formv("request_id") or None, formv("type_nc"), formv("description"), formv("severity"), formv("impact"), formv("consequence"), formv("decision_taken"), u["id"], u["name"], now(), "Ouverte"))
        audit("Déclaration non-conformité")
        return redirect("/quality/nonconformities")
    reqs = execute("SELECT id, auto_number, sample_number, patient_name, patient_firstname FROM requests WHERE status!='Supprimé' ORDER BY id DESC LIMIT 200", fetch=True)
    opts = "<option value=''>Non liée</option>" + "".join(f"<option value='{r['id']}'>{r['auto_number']} - {r.get('patient_name','')} {r.get('patient_firstname','')}</option>" for r in reqs)
    ncs = execute("SELECT * FROM non_conformities ORDER BY id DESC LIMIT 300", fetch=True)
    trs = "".join(f"<tr><td>{r['declared_at']}</td><td>{r.get('request_id') or '—'}</td><td>{r['type_nc']}</td><td>{r.get('severity','')}</td><td>{r.get('impact','')}</td><td>{r.get('consequence','')}</td><td>{r.get('decision_taken','')}</td></tr>" for r in ncs) or "<tr><td colspan='7'>Aucune non-conformité.</td></tr>"
    content = f"""<div class='card'><h2>Déclarer une non-conformité</h2><form method='post' class='grid g3'><label>Demande<select name='request_id'>{opts}</select></label><label>Type<select name='type_nc'><option>Échantillon non identifié</option><option>Mauvais étiquetage</option><option>Volume insuffisant</option><option>Pot non conforme</option><option>Demande incomplète</option><option>Retard d’acheminement</option><option>Mauvaise conservation</option><option>Discordance patient-échantillon</option><option>Contamination suspectée</option><option>Autre</option></select></label><label>Gravité<select name='severity'><option>Faible</option><option>Modéré</option><option>Élevé</option><option>Critique</option></select></label><label>Impact<select name='impact'><option>Faible</option><option>Modéré</option><option>Élevé</option><option>Critique</option></select></label><label>Conséquence<select name='consequence'><option>Résultat exploitable</option><option>Résultat interprétable avec prudence</option><option>Résultat douteux</option><option>Résultat non exploitable</option><option>Analyse rejetée</option></select></label><label>Décision<input name='decision_taken'></label><label style='grid-column:1/-1'>Description<textarea name='description'></textarea></label><button class='btn ok'>Enregistrer</button></form></div><div class='card'><h2>Registre</h2><table class='table'><tr><th>Date</th><th>Demande</th><th>Type</th><th>Gravité</th><th>Impact</th><th>Conséquence</th><th>Décision</th></tr>{trs}</table></div>"""
    return page("Non-conformités", content, u)

@app.route("/quality/capa", methods=["GET", "POST"])
@role_required("laboratoire", "chef_labo")
def capa(u):
    if request.method == "POST":
        execute("""INSERT INTO capa_actions(non_conformity_id,corrective_action,preventive_action,responsible,due_date,status,result,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)""", (formv("non_conformity_id") or None, formv("corrective_action"), formv("preventive_action"), formv("responsible"), formv("due_date"), formv("status"), formv("result"), u["id"], now(), now()))
        audit("Création CAPA")
        return redirect("/quality/capa")
    ncs = execute("SELECT id, type_nc, declared_at FROM non_conformities ORDER BY id DESC LIMIT 200", fetch=True)
    opts = "<option value=''>Non liée</option>" + "".join(f"<option value='{r['id']}'>#{r['id']} - {r['type_nc']}</option>" for r in ncs)
    rows_ = execute("SELECT * FROM capa_actions ORDER BY id DESC LIMIT 300", fetch=True)
    trs = "".join(f"<tr><td>{r['created_at']}</td><td>{r.get('non_conformity_id') or '—'}</td><td>{r.get('corrective_action','')}</td><td>{r.get('preventive_action','')}</td><td>{r.get('responsible','')}</td><td>{r.get('due_date','')}</td><td>{r.get('status','')}</td><td>{r.get('result','')}</td></tr>" for r in rows_) or "<tr><td colspan='8'>Aucune action CAPA.</td></tr>"
    content = f"""<div class='card'><h2>Actions correctives et préventives</h2><form method='post' class='grid g3'><label>Non-conformité<select name='non_conformity_id'>{opts}</select></label><label>Responsable<input name='responsible'></label><label>Date prévue<input type='date' name='due_date'></label><label>Statut<select name='status'><option>Ouverte</option><option>En cours</option><option>Résolue</option><option>Fermée</option></select></label><label style='grid-column:1/-1'>Action corrective<textarea name='corrective_action'></textarea></label><label style='grid-column:1/-1'>Action préventive<textarea name='preventive_action'></textarea></label><label style='grid-column:1/-1'>Résultat<textarea name='result'></textarea></label><button class='btn ok'>Enregistrer</button></form></div><div class='card'><h2>Registre CAPA</h2><table class='table'><tr><th>Date</th><th>NC</th><th>Corrective</th><th>Préventive</th><th>Responsable</th><th>Échéance</th><th>Statut</th><th>Résultat</th></tr>{trs}</table></div>"""
    return page("CAPA", content, u)

@app.route("/microbiology/resistance")
@role_required("laboratoire", "chef_labo")
def resistance_dashboard(u):
    rows_ = execute("""SELECT lr.culture_status, lr.culture_details, lr.antibiogram_json FROM lab_results lr JOIN requests rq ON rq.id=lr.request_id WHERE rq.status='Validé et envoyé' AND lr.antibiogram_json IS NOT NULL ORDER BY lr.request_id DESC""", fetch=True)
    counts, germs = {}, {}
    for r in rows_:
        if r.get('culture_status') == 'Positive':
            details = (r.get('culture_details') or 'Non renseigné').strip()
            germs[details] = germs.get(details, 0) + 1
        try:
            data = json.loads(r.get('antibiogram_json') or '[]')
        except Exception:
            data = []
        for a in data:
            if a.get('show') and a.get('interp') in ('S','I','R'):
                key = a.get('name') or 'Antibiotique'
                counts.setdefault(key, {'S':0,'I':0,'R':0})[a.get('interp')] += 1
    ab_rows = "".join(f"<tr><td>{k}</td><td>{v['S']}</td><td>{v['I']}</td><td>{v['R']}</td><td>{round(v['R']*100/max(1,(v['S']+v['I']+v['R'])),1)}%</td></tr>" for k,v in sorted(counts.items())) or "<tr><td colspan='5'>Aucune donnée.</td></tr>"
    germ_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in sorted(germs.items(), key=lambda x:x[1], reverse=True)) or "<tr><td colspan='2'>Aucun germe positif.</td></tr>"
    return page("Antibiorésistance", f"<div class='card'><h2>Surveillance de l’antibiorésistance</h2><p class='small'>Calcul automatique à partir des antibiogrammes validés.</p></div><div class='card'><h2>Résistance par antibiotique</h2><table class='table'><tr><th>Antibiotique</th><th>S</th><th>I</th><th>R</th><th>Taux R</th></tr>{ab_rows}</table></div><div class='card'><h2>Germes isolés</h2><table class='table'><tr><th>Germe / détails culture</th><th>Nombre</th></tr>{germ_rows}</table></div>", u)

@app.route("/quality/export/nonconformities.csv")
@role_required("laboratoire", "chef_labo")
def export_nonconformities(u):
    data = execute("SELECT declared_at, request_id, type_nc, severity, impact, consequence, decision_taken, declared_by_name FROM non_conformities ORDER BY id DESC", fetch=True)
    out = io.StringIO(); w = csv.writer(out, delimiter=';')
    w.writerow(['Date','Demande','Type','Gravité','Impact','Conséquence','Décision','Déclarant'])
    for r in data:
        w.writerow([r['declared_at'], r.get('request_id',''), r['type_nc'], r.get('severity',''), r.get('impact',''), r.get('consequence',''), r.get('decision_taken',''), r.get('declared_by_name','')])
    return Response(out.getvalue().encode('utf-8-sig'), mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=non_conformites_ecbu.csv'})

@app.route("/audit")
@role_required("admin")
def audit_page(u):
    data = execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500", fetch=True)
    trs = "".join(f"<tr><td>{r['created_at']}</td><td>{r.get('user_name','')}</td><td>{r['action']}</td><td>{r.get('ip_address','')}</td></tr>" for r in data)
    return page("Journal", f"<div class='card'><h2>Journal</h2><table class='table'><tr><th>Date</th><th>Utilisateur</th><th>Action</th><th>IP</th></tr>{trs}</table></div>", u)

def main():
    init_db()
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    args = ap.parse_args()
    app.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
