#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECBU Liaison Pro Cloud/Reseau - serveur web autonome.
Dependances externes: aucune. Python 3.10+.
Usage local: python server.py --host 0.0.0.0 --port 8000
"""
import argparse, base64, csv, datetime as dt, hashlib, hmac, html, os, secrets, sqlite3, sys, urllib.parse
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

APP_NAME = "ECBU Liaison Pro"
DB_PATH = os.environ.get("ECBU_DB", os.path.join(os.path.dirname(__file__), "ecbu_liaison.db"))
SECRET = os.environ.get("ECBU_SECRET", "change-this-secret-in-production-" + secrets.token_hex(16))

ANTIBIOTICS = [
    "Ampicilline (AMP10)", "Amoxicilline + acide clavulanique (AMC30)", "Pipéracilline/Tazobactam (TZP)",
    "Ceftriaxone (CRO30)", "Ceftazidime (CAZ30)", "Céfotaxime (CTX30)", "Céfoxitine (FOX30)",
    "Imipénème (IPM10)", "Méropénème (MEM10)", "Ertapénème (ETP10)", "Gentamicine (GEN10)",
    "Amikacine (AK30)", "Tobramycine (TOB10)", "Ciprofloxacine (CIP5)", "Norfloxacine (NOR10)",
    "Ofloxacine (OFX5)", "Lévofloxacine (LEV5)", "Cotrimoxazole (SXT25)", "Nitrofurantoïne (F/M300)",
    "Fosfomycine (FOS200)", "Doxycycline (DO30)", "Azithromycine (AZM15)", "Erythromycine (E15)",
    "Clindamycine (DA2)", "Vancomycine (VA30)", "Linézolide (LZD10)"
]

PREANALYTIC_RULES = [
    ("patient_informe", "Patient informé des conditions de prélèvement"),
    ("technique_maitrisee", "Technique de prélèvement maîtrisée par le patient"),
    ("toilette", "Toilette intime réalisée"),
    ("flacon_sterile", "Flacon stérile utilisé"),
    ("flacon_identifie", "Flacon correctement identifié"),
    ("volume_suffisant", "Volume d’urines suffisant"),
    ("absence_fuite", "Absence de fuite / flacon non souillé"),
    ("delai_conforme", "Délai miction–réception conforme selon procédure"),
    ("temperature_conforme", "Température/conservation conforme"),
    ("transport_conforme", "Conditions de transport conformes"),
    ("nature_conforme", "Nature/type de prélèvement conforme à la demande"),
    ("antibiotherapie_renseignee", "Antibiothérapie avant prélèvement renseignée"),
]

REQUEST_FIELDS = [
    "auto_number","sample_number","code_prelevement","date_prelevement","heure_prelevement","service_prescripteur",
    "patient_status","age","age_unit","sex","patient_antibiotics","patient_probe","sample_type","patient_informe_decl",
    "technique_maitrisee_decl","toilette_decl","flacon_sterile_decl","delai_miction_depot","temperature_conservation",
    "prescriber_name","patient_name","patient_firstname","patient_phone","clinical_context","exam_requested","urgent","observations_prescripteur",
    "created_by","created_by_name","status","conformity","rejection_reason","created_at","updated_at"
]

LAB_FIELDS = [
    "request_id","reception_date","reception_time","aspect","leucocytes","hematies","cellules_epitheliales","autres_micro",
    "gram_result","culture_status","culture_details","antibiogram_json","conclusion","validator_name","validator_title",
    "lab_operator_name","chief_validator_name","chief_validation_at","result_sent_at","quality_json"
]

def now(): return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def h(x): return html.escape(str(x or ""), quote=True)
def qs(params): return urllib.parse.urlencode(params)

def db_conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con=db_conn(); c=con.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','prescripteur','laboratoire','chef_labo')), service TEXT, active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL, suspended_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT, auto_number TEXT UNIQUE, sample_number TEXT, code_prelevement TEXT,
        date_prelevement TEXT, heure_prelevement TEXT, service_prescripteur TEXT, patient_status TEXT, age TEXT, age_unit TEXT, sex TEXT,
        patient_antibiotics TEXT, patient_probe TEXT, sample_type TEXT, patient_informe_decl TEXT, technique_maitrisee_decl TEXT,
        toilette_decl TEXT, flacon_sterile_decl TEXT, delai_miction_depot TEXT, temperature_conservation TEXT,
        prescriber_name TEXT, patient_name TEXT, patient_firstname TEXT, patient_phone TEXT, clinical_context TEXT, exam_requested TEXT,
        urgent TEXT, observations_prescripteur TEXT, created_by INTEGER NOT NULL, created_by_name TEXT, status TEXT NOT NULL,
        conformity TEXT DEFAULT 'Non évalué', rejection_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS lab_results(
        request_id INTEGER PRIMARY KEY, reception_date TEXT, reception_time TEXT, aspect TEXT, leucocytes TEXT, hematies TEXT,
        cellules_epitheliales TEXT, autres_micro TEXT, gram_result TEXT, culture_status TEXT, culture_details TEXT,
        antibiogram_json TEXT, conclusion TEXT, validator_name TEXT, validator_title TEXT, lab_operator_name TEXT,
        chief_validator_name TEXT, chief_validation_at TEXT, result_sent_at TEXT, quality_json TEXT,
        FOREIGN KEY(request_id) REFERENCES requests(id) ON DELETE CASCADE
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT, action TEXT, created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)""")
    con.commit(); con.close()

def has_admin():
    with db_conn() as con:
        return con.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] > 0

def hash_password(pwd, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt.encode(), 120000)
    return salt + '$' + base64.b64encode(digest).decode()

def verify_password(stored, pwd):
    try:
        salt, digest = stored.split('$',1)
        return hmac.compare_digest(hash_password(pwd, salt).split('$',1)[1], digest)
    except Exception: return False

def sign(value):
    sig = hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return value + '.' + sig

def unsign(value):
    try:
        raw, sig = value.rsplit('.',1)
        expected = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected): return raw
    except Exception: pass
    return None

def audit(user, action):
    with db_conn() as con:
        con.execute("INSERT INTO audit(user_id,user_name,action,created_at) VALUES(?,?,?,?)", (user.get('id') if user else None, user.get('name') if user else '', action, now()))
        con.commit()

def layout(user, title, content):
    menu = ''
    if user:
        items=[]
        if user['role']=='admin': items=[('/admin/users','Utilisateurs'),('/admin/export','Exports'),('/audit','Journal')]
        elif user['role']=='prescripteur': items=[('/request/new','Nouvelle demande'),('/requests','Mes demandes'),('/archive','Archives du service')]
        elif user['role']=='laboratoire': items=[('/lab/inbox','Demandes reçues'),('/lab/processed','Analyses traitées')]
        elif user['role']=='chef_labo': items=[('/chief/pending','À valider'),('/chief/all','Tous les bilans'),('/lab/processed','Archives labo')]
        menu = ''.join(f'<a class="nav" href="{u}">{h(t)}</a>' for u,t in items) + '<a class="nav danger" href="/logout">Déconnexion</a>'
    return f"""<!doctype html><html lang='fr'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{h(title)} - {APP_NAME}</title><style>
:root{{--blue:#075985;--blue2:#0284c7;--ink:#0f172a;--mut:#64748b;--line:#dbe7f0;--bg:#f4f8fb;--ok:#15803d;--bad:#b91c1c;--warn:#a16207}}
*{{box-sizing:border-box}} body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:linear-gradient(135deg,#eff6ff,#f8fafc);color:var(--ink)}}
a{{color:inherit}} .shell{{display:grid;grid-template-columns:280px 1fr;min-height:100vh}} .side{{background:#062b49;color:#fff;padding:22px;position:sticky;top:0;height:100vh}}
.logo{{width:48px;height:48px;border-radius:15px;background:linear-gradient(135deg,#38bdf8,#14b8a6);display:grid;place-items:center;font-weight:900}}
.brand{{display:flex;gap:12px;align-items:center;margin-bottom:22px}} .brand h1{{font-size:20px;margin:0}} .brand p{{font-size:12px;color:#bfdbfe;margin:3px 0 0}}
.nav{{display:block;text-decoration:none;padding:12px 14px;border-radius:14px;margin:6px 0;color:#dbeafe;font-weight:700}} .nav:hover{{background:#0b4c78}} .danger{{color:#fecaca}}
.top{{background:rgba(255,255,255,.9);border-bottom:1px solid var(--line);padding:16px 24px;display:flex;justify-content:space-between;align-items:center}}
.content{{padding:24px;max-width:1480px}} .card{{background:#fff;border:1px solid #e2e8f0;border-radius:22px;box-shadow:0 14px 40px rgba(2,132,199,.08);padding:20px;margin-bottom:18px}}
.grid{{display:grid;gap:13px}} .g2{{grid-template-columns:repeat(2,1fr)}} .g3{{grid-template-columns:repeat(3,1fr)}} .g4{{grid-template-columns:repeat(4,1fr)}} label{{font-size:13px;color:#475569;font-weight:700}}
input,select,textarea{{width:100%;padding:11px 12px;border:1px solid #cbd5e1;border-radius:12px;background:#fbfdff;margin-top:5px;font-size:14px}} textarea{{min-height:82px}}
.btn{{border:0;border-radius:12px;background:var(--blue);color:white;padding:11px 15px;font-weight:800;cursor:pointer;text-decoration:none;display:inline-block}} .btn.sec{{background:#e2e8f0;color:#0f172a}} .btn.ok{{background:#15803d}} .btn.bad{{background:#b91c1c}}
.msg{{padding:12px 14px;border-left:5px solid var(--blue2);background:#eff6ff;border-radius:14px;color:#1e3a8a}} .warn{{border-left-color:#f97316;background:#fff7ed;color:#7c2d12}}
.table{{width:100%;border-collapse:collapse}} .table th,.table td{{padding:10px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top}} .table th{{background:#f8fafc;color:#475569;font-size:12px}}
.pill{{display:inline-block;border-radius:99px;padding:5px 10px;font-size:12px;font-weight:900}} .p-ok{{background:#dcfce7;color:#166534}} .p-bad{{background:#fee2e2;color:#991b1b}} .p-wait{{background:#fef3c7;color:#92400e}}
.login{{max-width:560px;margin:8vh auto}} .small{{color:#64748b;font-size:12px}} .kpi{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:18px;padding:16px}} .kpi b{{font-size:28px;color:#075985}}
.reportPage{{width:210mm;min-height:297mm;margin:0 auto;background:white;color:#000;padding:10mm;border:1px solid #111;font-family:Arial,sans-serif;font-size:11.2pt;line-height:1.25}}
.reportPage h1{{font-size:16pt;text-align:center;margin:2mm 0;text-transform:uppercase}} .reportPage .center{{text-align:center}} .row{{display:grid;grid-template-columns:1fr 1fr;gap:2mm 12mm;margin:2mm 0}}
.box{{border:1px solid #111;padding:2.5mm;margin-top:3mm;min-height:16mm}} .boxTitle{{font-weight:900;text-align:center;border-bottom:1px solid #111;margin:-2.5mm -2.5mm 2mm -2.5mm;padding:1.5mm;text-transform:uppercase}}
.abg{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:2mm}} .abg>div{{border:1px solid #333;min-height:26mm;padding:2mm}} .sign{{margin-top:8mm;text-align:right}}
@media(max-width:900px){{.shell{{grid-template-columns:1fr}}.side{{height:auto;position:relative}}.g2,.g3,.g4{{grid-template-columns:1fr}}.content{{padding:12px}}.top{{padding:12px}}.reportPage{{width:100%;min-height:auto;padding:6mm;font-size:10pt}}}}
@media print{{body{{background:#fff}}.side,.top,.noPrint,.card:not(.printCard){{display:none!important}}.shell{{display:block}}.content{{padding:0}}.reportPage{{border:0;margin:0;width:210mm;height:297mm;overflow:hidden}}}}
</style></head><body>{('<div class="shell"><aside class="side"><div class="brand"><div class="logo">EC</div><div><h1>ECBU Liaison Pro</h1><p>Serveur clinique sécurisé</p></div></div>'+menu+'</aside><main><div class="top"><b>'+h(title)+'</b><span class="small">'+h(user['name'])+' — '+h(user['role'])+'</span></div><div class="content">'+content+'</div></main></div>') if user else content}</body></html>"""

def pill(status):
    cls = 'p-ok' if status in ('Validé et envoyé','Conforme') else ('p-bad' if status in ('Rejeté','Non conforme','Supprimé') else 'p-wait')
    return f'<span class="pill {cls}">{h(status)}</span>'

class App(BaseHTTPRequestHandler):
    server_version = "ECBUHTTP/1.0"
    def log_message(self, fmt, *args): sys.stderr.write("[%s] %s\n" % (now(), fmt%args))
    def read_post(self):
        n = int(self.headers.get('Content-Length',0)); data=self.rfile.read(n).decode('utf-8') if n else ''
        return {k:v[0] if len(v)==1 else v for k,v in urllib.parse.parse_qs(data).items()}
    def redirect(self, path): self.send_response(303); self.send_header('Location', path); self.end_headers()
    def send_html(self, html_text, status=200):
        b=html_text.encode('utf-8'); self.send_response(status); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def send_csv(self, filename, rows):
        import io
        s=io.StringIO(); w=csv.writer(s, delimiter=';'); w.writerows(rows); b=s.getvalue().encode('utf-8-sig')
        self.send_response(200); self.send_header('Content-Type','text/csv; charset=utf-8'); self.send_header('Content-Disposition',f'attachment; filename="{filename}"'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def get_user(self):
        c=cookies.SimpleCookie(self.headers.get('Cookie','')); val=c.get('session')
        if not val: return None
        raw=unsign(val.value)
        if not raw: return None
        with db_conn() as con:
            u=con.execute("SELECT * FROM users WHERE id=? AND active=1",(raw,)).fetchone()
            return dict(u) if u else None
    def require(self, roles):
        u=self.get_user()
        if not u: self.redirect('/login'); return None
        if u['role'] not in roles: self.send_html(layout(u,'Accès interdit','<div class="card"><h2>Accès interdit</h2><p>Votre rôle ne permet pas d’ouvrir cette zone.</p></div>'),403); return None
        return u
    def do_GET(self):
        path=urllib.parse.urlparse(self.path).path
        try:
            if path in ('/','/login'): return self.page_login()
            if path=='/register': return self.page_register()
            if path=='/logout': return self.logout()
            if path=='/admin/users': return self.admin_users()
            if path=='/admin/export': return self.admin_export()
            if path=='/audit': return self.audit_page()
            if path=='/request/new': return self.new_request()
            if path=='/requests': return self.requests_page('mine')
            if path=='/archive': return self.requests_page('archive')
            if path=='/lab/inbox': return self.lab_inbox()
            if path=='/lab/processed': return self.lab_processed()
            if path=='/lab/edit': return self.lab_edit()
            if path=='/chief/pending': return self.chief_pending()
            if path=='/chief/all': return self.chief_all()
            if path=='/report': return self.report()
            if path=='/export/requests.csv': return self.export_requests()
            self.send_html('<h1>404</h1>',404)
        except Exception as e:
            self.send_html(layout(None,'Erreur interne',f'<div class="login card"><h1>Erreur interne du serveur</h1><p>Erreur capturée : {h(type(e).__name__)} — {h(str(e))}</p><p>Copie cette erreur pour correction.</p></div>'),500)
    def do_POST(self):
        path=urllib.parse.urlparse(self.path).path
        try:
            if path=='/setup': return self.setup_admin()
            if path=='/register': return self.register_user()
            if path=='/login': return self.login()
            if path=='/admin/create-user': return self.create_user()
            if path=='/admin/toggle-user': return self.toggle_user()
            if path=='/request/create': return self.create_request()
            if path=='/request/cancel': return self.cancel_request()
            if path=='/lab/save': return self.lab_save(send=False)
            if path=='/lab/reject': return self.lab_reject()
            if path=='/chief/validate': return self.chief_validate()
            self.send_html('<h1>404</h1>',404)
        except Exception as e:
            self.send_html(layout(None,'Erreur interne',f'<div class="login card"><h1>Erreur interne du serveur</h1><p>Erreur capturée : {h(type(e).__name__)} — {h(str(e))}</p><p>Copie cette erreur pour correction.</p></div>'),500)
    def page_login(self):
        if not has_admin():
            content=f"""<div class='login card'><div class='logo' style='margin:auto'>EC</div><h1 class='center'>Créer l’administrateur unique</h1><div class='msg'>Le site accepte un seul compte administrateur. Aucun autre compte ne peut être créé sans autorisation de cet administrateur.</div><form method='post' action='/setup' class='grid'><label>Nom complet<input name='name' required></label><label>Email<input name='email' type='email' required></label><label>Mot de passe<input name='password' type='password' minlength='8' required></label><button class='btn'>Créer l’administrateur</button></form></div>"""
        else:
            content="""<div class='login card'><div class='logo' style='margin:auto'>EC</div><h1 class='center'>Connexion sécurisée</h1><p class='small center'>Aucun identifiant n’est affiché publiquement.</p><form method='post' action='/login' class='grid'><label>Email<input name='email' type='email' autocomplete='username' required></label><label>Mot de passe<input name='password' type='password' autocomplete='current-password' required></label><button class='btn'>Connexion</button></form><p class='center'><a href='/register'>Créer une demande de compte</a></p></div>"""
        self.send_html(layout(None,'Connexion',content))
    def page_register(self):
        if not has_admin():
            return self.redirect('/login')
        content="""<div class='login card'><div class='logo' style='margin:auto'>EC</div><h1 class='center'>Créer une demande de compte</h1>
        <div class='msg'>Votre compte sera créé en attente de validation. Vous ne pourrez pas naviguer dans l’application tant que l’administrateur unique ne l’aura pas autorisé.</div>
        <form method='post' action='/register' class='grid'>
        <label>Nom complet<input name='name' required></label>
        <label>Email<input name='email' type='email' required></label>
        <label>Mot de passe<input name='password' type='password' minlength='8' required></label>
        <label>Rôle demandé<select name='role' required>
            <option value='prescripteur'>Clinicien prescripteur</option>
            <option value='laboratoire'>Technicien laboratoire</option>
            <option value='chef_labo'>Chef service laboratoire</option>
        </select></label>
        <label>Service / unité<input name='service' required placeholder='Ex : Médecine, Urgences, Bactériologie'></label>
        <button class='btn'>Envoyer la demande de compte</button>
        </form><p class='center'><a href='/login'>Retour à la connexion</a></p></div>"""
        self.send_html(layout(None,'Création de compte',content))

    def register_user(self):
        if not has_admin():
            return self.redirect('/login')
        p=self.read_post()
        name=p.get('name','').strip()
        email=p.get('email','').strip().lower()
        password=p.get('password','')
        role=p.get('role','')
        service=p.get('service','').strip()
        if role not in ('prescripteur','laboratoire','chef_labo') or not name or not email or len(password)<8 or not service:
            return self.send_html(layout(None,'Erreur',"<div class='login card'><h1>Demande refusée</h1><p>Informations incomplètes. Le mot de passe doit contenir au moins 8 caractères.</p><a class='btn' href='/register'>Recommencer</a></div>"),400)
        try:
            with db_conn() as con:
                con.execute("INSERT INTO users(name,email,password_hash,role,service,active,created_at) VALUES(?,?,?,?,?,?,?)",
                    (name,email,hash_password(password),role,service,0,now()))
                con.commit()
        except sqlite3.IntegrityError:
            return self.send_html(layout(None,'Erreur',"<div class='login card'><h1>Email déjà utilisé</h1><p>Un compte existe déjà avec cet email.</p><a class='btn' href='/login'>Retour</a></div>"),400)
        audit(None,'Demande de création de compte : '+email)
        self.send_html(layout(None,'Compte en attente',"<div class='login card'><h1>Demande envoyée</h1><div class='msg'>Votre compte a été créé, mais il est en attente de validation par l’administrateur. Vous pourrez vous connecter après autorisation.</div><a class='btn' href='/login'>Retour à la connexion</a></div>"))

    def setup_admin(self):
        if has_admin(): return self.redirect('/login')
        p=self.read_post();
        with db_conn() as con:
            con.execute("INSERT INTO users(name,email,password_hash,role,service,active,created_at) VALUES(?,?,?,?,?,?,?)",(p['name'].strip(),p['email'].strip().lower(),hash_password(p['password']),'admin','Administration',1,now()))
            con.commit()
        self.redirect('/login')
    def login(self):
        p=self.read_post(); email=p.get('email','').strip().lower(); pwd=p.get('password','')
        with db_conn() as con:
            u=con.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        if not u or not verify_password(u['password_hash'],pwd):
            return self.send_html(layout(None,'Connexion',"<div class='login card'><h1>Accès refusé</h1><p>Email ou mot de passe incorrect.</p><a class='btn' href='/login'>Réessayer</a></div>"),401)
        if not u['active']:
            return self.send_html(layout(None,'Compte en attente',"<div class='login card'><h1>Compte non autorisé</h1><p>Votre compte est créé, mais il n’a pas encore été validé par l’administrateur. Contactez l’administrateur du système.</p><a class='btn' href='/login'>Retour</a></div>"),403)
        self.send_response(303); self.send_header('Location','/admin/users' if u['role']=='admin' else ('/requests' if u['role']=='prescripteur' else ('/chief/pending' if u['role']=='chef_labo' else '/lab/inbox')))
        ck=cookies.SimpleCookie(); ck['session']=sign(str(u['id'])); ck['session']['path']='/'; ck['session']['httponly']=True; self.send_header('Set-Cookie', ck.output(header=''))
        self.end_headers(); audit(dict(u),'Connexion')
    def logout(self):
        self.send_response(303); self.send_header('Location','/login'); ck=cookies.SimpleCookie(); ck['session']=''; ck['session']['path']='/'; ck['session']['expires']='Thu, 01 Jan 1970 00:00:00 GMT'; self.send_header('Set-Cookie', ck.output(header='')); self.end_headers()
    def admin_users(self):
        u=self.require(['admin']);
        if not u: return
        with db_conn() as con: users=con.execute("SELECT * FROM users ORDER BY role,name").fetchall()
        rows=''
        for x in users:
            status = 'Actif' if x['active'] else 'En attente / Suspendu'
            action = ''
            if x['role']!='admin':
                action_label = 'Suspendre' if x['active'] else 'Valider / Réactiver'
                action = f"<form method='post' action='/admin/toggle-user'><input type='hidden' name='id' value='{x['id']}'><button class='btn sec'>{action_label}</button></form>"
            rows += f"<tr><td>{h(x['name'])}</td><td>{h(x['email'])}</td><td>{h(x['role'])}</td><td>{h(x['service'])}</td><td>{pill(status)}</td><td>{action}</td></tr>"
        content=f"""<div class='card'><h2>Créer directement un compte autorisé</h2><div class='msg warn'>Un seul administrateur est accepté. Les utilisateurs peuvent demander eux-mêmes un compte, mais ils ne peuvent pas accéder à l’application tant que l’administrateur ne valide pas leur compte. L’administrateur gère les comptes, mais ne voit pas les données confidentielles des bilans.</div><form method='post' action='/admin/create-user' class='grid g4'><label>Nom<input name='name' required></label><label>Email<input name='email' type='email' required></label><label>Mot de passe temporaire<input name='password' type='password' minlength='8' required></label><label>Rôle<select name='role'><option value='prescripteur'>Clinicien prescripteur</option><option value='laboratoire'>Technicien laboratoire</option><option value='chef_labo'>Chef service laboratoire</option></select></label><label>Service<input name='service' required></label><div><br><button class='btn'>Créer le compte</button></div></form></div><div class='card'><h2>Comptes</h2><table class='table'><tr><th>Nom</th><th>Email</th><th>Rôle</th><th>Service</th><th>Statut</th><th>Action</th></tr>{rows}</table></div>"""
        self.send_html(layout(u,'Utilisateurs',content))
    def create_user(self):
        u=self.require(['admin']);
        if not u: return
        p=self.read_post(); role=p['role']
        if role=='admin': return self.redirect('/admin/users')
        with db_conn() as con:
            con.execute("INSERT INTO users(name,email,password_hash,role,service,active,created_at) VALUES(?,?,?,?,?,?,?)",(p['name'].strip(),p['email'].strip().lower(),hash_password(p['password']),role,p['service'].strip(),1,now()))
            con.commit()
        audit(u,'Création compte '+p['email']); self.redirect('/admin/users')
    def toggle_user(self):
        u=self.require(['admin']);
        if not u: return
        p=self.read_post();
        with db_conn() as con:
            target=con.execute("SELECT * FROM users WHERE id=?",(p['id'],)).fetchone()
            if target and target['role']!='admin':
                new=0 if target['active'] else 1
                con.execute("UPDATE users SET active=?, suspended_at=? WHERE id=?",(new, now() if not new else None, p['id'])); con.commit()
        audit(u,'Suspension/réactivation compte'); self.redirect('/admin/users')
    def new_request(self):
        u=self.require(['prescripteur']);
        if not u: return
        content=f"""<div class='card'><h2>Fiche de demande ECBU adressée au laboratoire</h2><div class='msg'>Tous les renseignements utiles à la réalisation d’un ECBU sont demandés. Le laboratoire complètera le contrôle de conformité et attribuera son propre N° d’échantillon.</div><form method='post' action='/request/create' class='grid g3'>
<label>Code du prélèvement<input name='code_prelevement'></label><label>Date du prélèvement<input type='date' name='date_prelevement' required></label><label>Heure du prélèvement<input type='time' name='heure_prelevement' required></label>
<label>Nom du patient<input name='patient_name' required></label><label>Prénoms du patient<input name='patient_firstname' required></label><label>Téléphone / contact patient<input name='patient_phone'></label>
<label>Âge<input name='age' required></label><label>Unité âge<select name='age_unit'><option>Ans</option><option>Mois</option><option>Jours</option></select></label><label>Sexe<select name='sex'><option>Masculin</option><option>Féminin</option><option>Non précisé</option></select></label>
<label>Service prescripteur<input name='service_prescripteur' value='{h(u['service'])}' required></label><label>Médecin prescripteur<input name='prescriber_name' value='{h(u['name'])}' required></label><label>Statut patient<select name='patient_status'><option>Hospitalisé</option><option>Externe</option><option>Ambulatoire</option></select></label>
<label>Examen demandé<select name='exam_requested'><option>ECBU</option><option>Culture urine + antibiogramme si positif</option></select></label><label>Urgence<select name='urgent'><option>Non</option><option>Oui</option></select></label><label>Patient sous antibiotiques<select name='patient_antibiotics'><option>Non</option><option>Oui</option><option>Non renseigné</option></select></label>
<label>Patient sous sonde<select name='patient_probe'><option>Non</option><option>Oui</option></select></label><label>Type de prélèvement<select name='sample_type'><option>Jet moyen</option><option>Sonde urinaire</option><option>Poche collectrice</option><option>Autre</option></select></label><label>Délai miction-dépôt<select name='delai_miction_depot'><option>≤ 2 h</option><option>2–4 h</option><option>> 4 h</option><option>Non renseigné</option></select></label>
<label>Température de conservation<select name='temperature_conservation'><option>Réfrigération</option><option>Ambiante</option><option>Non renseignée</option></select></label><label>Patient informé ?<select name='patient_informe_decl'><option>Oui</option><option>Non</option></select></label><label>Technique maîtrisée ?<select name='technique_maitrisee_decl'><option>Oui</option><option>Non</option></select></label>
<label>Toilette intime réalisée ?<select name='toilette_decl'><option>Oui</option><option>Non</option></select></label><label>Flacon stérile utilisé ?<select name='flacon_sterile_decl'><option>Oui</option><option>Non</option></select></label><label>Contexte clinique<textarea name='clinical_context' placeholder='Fièvre, dysurie, grossesse, sonde, contrôle, etc.'></textarea></label>
<label class='g3' style='grid-column:1/-1'>Observations du prescripteur<textarea name='observations_prescripteur'></textarea></label><div><button class='btn ok'>Envoyer au laboratoire</button></div></form></div>"""
        self.send_html(layout(u,'Nouvelle demande',content))
    def create_request(self):
        u=self.require(['prescripteur']);
        if not u: return
        p=self.read_post()
        with db_conn() as con:
            count=con.execute("SELECT COUNT(*) FROM requests").fetchone()[0]+1
            auto=f"DEM-{dt.datetime.now().year}-{count:05d}"
            vals={k:p.get(k,'') for k in REQUEST_FIELDS}; vals.update({'auto_number':auto,'created_by':u['id'],'created_by_name':u['name'],'status':'Envoyé au laboratoire','conformity':'Non évalué','created_at':now(),'updated_at':now()})
            con.execute("""INSERT INTO requests(auto_number,sample_number,code_prelevement,date_prelevement,heure_prelevement,service_prescripteur,patient_status,age,age_unit,sex,patient_antibiotics,patient_probe,sample_type,patient_informe_decl,technique_maitrisee_decl,toilette_decl,flacon_sterile_decl,delai_miction_depot,temperature_conservation,prescriber_name,patient_name,patient_firstname,patient_phone,clinical_context,exam_requested,urgent,observations_prescripteur,created_by,created_by_name,status,conformity,rejection_reason,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            tuple(vals[k] for k in REQUEST_FIELDS))
            con.commit()
        audit(u,'Nouvelle demande '+auto); self.redirect('/requests')
    def list_requests_table(self, u, rows, title, lab_actions=False, chief=False):
        trs=''.join(f"<tr><td>{h(r['auto_number'])}</td><td>{h(r['sample_number'] or 'À attribuer')}</td><td>{h(r['service_prescripteur'])}</td><td>{h(r['patient_name'])} {h(r['patient_firstname'])}</td><td>{pill(r['status'])}</td><td>{pill(r['conformity'])}</td><td>{self.action_buttons(r, lab_actions, chief)}</td></tr>" for r in rows)
        return layout(u,title,f"<div class='card'><h2>{h(title)}</h2><table class='table'><tr><th>N° demande</th><th>N° échantillon</th><th>Service</th><th>Patient</th><th>Statut</th><th>Conformité</th><th>Action</th></tr>{trs or '<tr><td colspan=7>Aucune donnée.</td></tr>'}</table></div>")
    def action_buttons(self,r,lab=False,chief=False):
        s=f"<a class='btn sec' href='/report?id={r['id']}'>Bon</a> "
        if lab: s+=f"<a class='btn' href='/lab/edit?id={r['id']}'>Traiter</a>"
        if chief and r['status']=='En attente validation chef': s+=f" <form style='display:inline' method='post' action='/chief/validate'><input type='hidden' name='id' value='{r['id']}'><button class='btn ok'>Valider et envoyer</button></form>"
        if r['status'] not in ('Validé et envoyé','Rejeté','Supprimé') and not lab and not chief: s+=f" <form style='display:inline' method='post' action='/request/cancel'><input type='hidden' name='id' value='{r['id']}'><button class='btn bad'>Annuler</button></form>"
        return s
    def requests_page(self, mode):
        u=self.require(['prescripteur']);
        if not u: return
        with db_conn() as con:
            rows=con.execute("SELECT * FROM requests WHERE created_by=? AND status!='Supprimé' ORDER BY id DESC",(u['id'],)).fetchall()
        self.send_html(self.list_requests_table(u, rows, 'Archives du service' if mode=='archive' else 'Mes demandes'))
    def cancel_request(self):
        u=self.require(['prescripteur']);
        if not u: return
        p=self.read_post()
        with db_conn() as con:
            con.execute("UPDATE requests SET status='Supprimé', updated_at=? WHERE id=? AND created_by=? AND status NOT IN ('Validé et envoyé')",(now(),p['id'],u['id'])); con.commit()
        audit(u,'Suppression/annulation demande'); self.redirect('/requests')
    def lab_inbox(self):
        u=self.require(['laboratoire']);
        if not u:return
        with db_conn() as con: rows=con.execute("SELECT * FROM requests WHERE status IN ('Envoyé au laboratoire','En cours laboratoire','Rejeté') ORDER BY id DESC").fetchall()
        self.send_html(self.list_requests_table(u,rows,'Demandes reçues au laboratoire',lab_actions=True))
    def lab_processed(self):
        u=self.require(['laboratoire','chef_labo']);
        if not u:return
        with db_conn() as con: rows=con.execute("SELECT * FROM requests WHERE status IN ('En attente validation chef','Validé et envoyé','Rejeté') ORDER BY id DESC").fetchall()
        self.send_html(self.list_requests_table(u,rows,'Archives laboratoire',lab_actions=(u['role']=='laboratoire'),chief=(u['role']=='chef_labo')))
    def lab_edit(self):
        u=self.require(['laboratoire']);
        if not u: return
        q=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query); rid=q.get('id',[''])[0]
        with db_conn() as con:
            r=con.execute("SELECT * FROM requests WHERE id=?",(rid,)).fetchone(); lab=con.execute("SELECT * FROM lab_results WHERE request_id=?",(rid,)).fetchone()
        if not r: return self.redirect('/lab/inbox')
        l=dict(lab) if lab else {}
        checks=''.join(f"<label><input type='checkbox' name='{key}' {'checked' if (l.get('quality_json') or '').find(key)>=0 else ''}> {h(label)}</label>" for key,label in PREANALYTIC_RULES)
        atb_rows=''.join(f"<tr><td>{h(a)}</td><td><input name='diam_{i}'></td><td><select name='interp_{i}'><option>ND</option><option>S</option><option>I</option><option>R</option></select></td><td><select name='show_{i}'><option>Non</option><option>Oui</option></select></td></tr>" for i,a in enumerate(ANTIBIOTICS))
        content=f"""<div class='card'><h2>Traitement laboratoire — {h(r['auto_number'])}</h2><form method='post' action='/lab/save'><input type='hidden' name='id' value='{h(r['id'])}'><div class='grid g3'><label>N° d’échantillon attribué par le laboratoire<input name='sample_number' value='{h(r['sample_number'])}' required></label><label>Date réception<input type='date' name='reception_date' value='{h(l.get('reception_date',''))}' required></label><label>Heure réception<input type='time' name='reception_time' value='{h(l.get('reception_time',''))}' required></label></div><h3>Contrôle conformité ECBU</h3><div class='grid g3'>{checks}</div><h3>Résultats</h3><div class='grid g3'><label>Aspect<input name='aspect' value='{h(l.get('aspect',''))}'></label><label>Leucocytes GB/ml<input name='leucocytes' value='{h(l.get('leucocytes',''))}'></label><label>Hématies GR/ml<input name='hematies' value='{h(l.get('hematies',''))}'></label><label>Cellules épithéliales<input name='cellules_epitheliales' value='{h(l.get('cellules_epitheliales',''))}'></label><label>Autres<input name='autres_micro' value='{h(l.get('autres_micro',''))}'></label><label>Culture<select name='culture_status'><option>Positive</option><option>Négative</option><option>Contaminée</option><option>Rejetée</option></select></label><label style='grid-column:1/-1'>Coloration de Gram<textarea name='gram_result'>{h(l.get('gram_result',''))}</textarea></label><label style='grid-column:1/-1'>Culture / germe isolé<textarea name='culture_details'>{h(l.get('culture_details',''))}</textarea></label><label style='grid-column:1/-1'>Conclusion<textarea name='conclusion'>{h(l.get('conclusion',''))}</textarea></label><label>Nom du validateur proposé<input name='validator_name' value='{h(l.get('validator_name',''))}'></label><label>Titre du validateur<input name='validator_title' value='{h(l.get('validator_title',''))}' placeholder='Ex: Ir Biomédical, PhD'></label></div><h3>Antibiogramme EUCAST</h3><div class='msg'>Si culture négative, contaminée ou rejetée, le bon affichera automatiquement : Antibiogramme non applicable.</div><table class='table'><tr><th>Antibiotique</th><th>Diamètre</th><th>S/I/R</th><th>Afficher</th></tr>{atb_rows}</table><br><button class='btn ok'>Enregistrer et envoyer au chef de laboratoire</button></form><form method='post' action='/lab/reject' style='margin-top:10px'><input type='hidden' name='id' value='{h(r['id'])}'><label>Motif de rejet / non-conformité<textarea name='reason' required></textarea></label><button class='btn bad'>Rejeter le prélèvement</button></form></div>"""
        self.send_html(layout(u,'Traitement laboratoire',content))
    def lab_save(self, send=False):
        u=self.require(['laboratoire']);
        if not u:return
        p=self.read_post(); rid=p['id']
        quality=[key for key,_ in PREANALYTIC_RULES if p.get(key)=='on']; conformity='Conforme' if len(quality)==len(PREANALYTIC_RULES) else 'Non conforme'
        atbs=[]
        for i,a in enumerate(ANTIBIOTICS): atbs.append({'name':a,'diam':p.get(f'diam_{i}',''),'interp':p.get(f'interp_{i}','ND'),'show':p.get(f'show_{i}')=='Oui'})
        import json
        with db_conn() as con:
            con.execute("UPDATE requests SET sample_number=?, status='En attente validation chef', conformity=?, updated_at=? WHERE id=?",(p.get('sample_number','').strip(),conformity,now(),rid))
            con.execute("""INSERT INTO lab_results(request_id,reception_date,reception_time,aspect,leucocytes,hematies,cellules_epitheliales,autres_micro,gram_result,culture_status,culture_details,antibiogram_json,conclusion,validator_name,validator_title,lab_operator_name,quality_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(request_id) DO UPDATE SET reception_date=excluded.reception_date,reception_time=excluded.reception_time,aspect=excluded.aspect,leucocytes=excluded.leucocytes,hematies=excluded.hematies,cellules_epitheliales=excluded.cellules_epitheliales,autres_micro=excluded.autres_micro,gram_result=excluded.gram_result,culture_status=excluded.culture_status,culture_details=excluded.culture_details,antibiogram_json=excluded.antibiogram_json,conclusion=excluded.conclusion,validator_name=excluded.validator_name,validator_title=excluded.validator_title,lab_operator_name=excluded.lab_operator_name,quality_json=excluded.quality_json""",
            (rid,p.get('reception_date',''),p.get('reception_time',''),p.get('aspect',''),p.get('leucocytes',''),p.get('hematies',''),p.get('cellules_epitheliales',''),p.get('autres_micro',''),p.get('gram_result',''),p.get('culture_status',''),p.get('culture_details',''),json.dumps(atbs,ensure_ascii=False),p.get('conclusion',''),p.get('validator_name',''),p.get('validator_title',''),u['name'],json.dumps(quality,ensure_ascii=False)))
            con.commit()
        audit(u,'Résultat envoyé au chef labo pour validation'); self.redirect('/lab/processed')
    def lab_reject(self):
        u=self.require(['laboratoire']);
        if not u:return
        p=self.read_post()
        with db_conn() as con:
            con.execute("UPDATE requests SET status='Rejeté', conformity='Non conforme', rejection_reason=?, updated_at=? WHERE id=?",(p['reason'],now(),p['id'])); con.commit()
        audit(u,'Prélèvement rejeté'); self.redirect('/lab/inbox')
    def chief_pending(self):
        u=self.require(['chef_labo']);
        if not u:return
        with db_conn() as con: rows=con.execute("SELECT * FROM requests WHERE status='En attente validation chef' ORDER BY id DESC").fetchall()
        self.send_html(self.list_requests_table(u,rows,'Résultats à valider par le chef de laboratoire',chief=True))
    def chief_all(self):
        u=self.require(['chef_labo']);
        if not u:return
        with db_conn() as con: rows=con.execute("SELECT * FROM requests WHERE status!='Supprimé' ORDER BY id DESC").fetchall()
        self.send_html(self.list_requests_table(u,rows,'Tous les bilans du laboratoire',chief=True))
    def chief_validate(self):
        u=self.require(['chef_labo']);
        if not u:return
        p=self.read_post()
        with db_conn() as con:
            con.execute("UPDATE requests SET status='Validé et envoyé', updated_at=? WHERE id=?",(now(),p['id']))
            con.execute("UPDATE lab_results SET chief_validator_name=?, chief_validation_at=?, result_sent_at=? WHERE request_id=?",(u['name'],now(),now(),p['id']))
            con.commit()
        audit(u,'Validation finale et envoi au clinicien'); self.redirect('/chief/pending')
    def report(self):
        u=self.get_user();
        if not u: return self.redirect('/login')
        q=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query); rid=q.get('id',[''])[0]
        with db_conn() as con:
            r=con.execute("SELECT * FROM requests WHERE id=?",(rid,)).fetchone(); l=con.execute("SELECT * FROM lab_results WHERE request_id=?",(rid,)).fetchone()
        if not r: return self.redirect('/requests')
        if u['role']=='admin': return self.send_html(layout(u,'Accès interdit','<div class="card">Les données médicales confidentielles ne sont pas accessibles à l’administrateur.</div>'),403)
        if u['role']=='prescripteur' and r['created_by']!=u['id']: return self.send_html(layout(u,'Accès interdit','<div class="card">Ce résultat appartient à un autre clinicien.</div>'),403)
        content=self.report_html(dict(r), dict(l) if l else {})
        self.send_html(layout(u,'Bon de résultat',content))
    def report_html(self,r,l):
        import json
        culture=l.get('culture_status','')
        if culture=='Positive':
            groups={'S':[],'I':[],'R':[]}
            for a in json.loads(l.get('antibiogram_json') or '[]'):
                if a.get('show') and a.get('interp') in groups:
                    groups[a['interp']].append(h(a['name'])+(f" ({h(a.get('diam',''))} mm)" if a.get('diam') else ''))
            atb=f"<div class='abg'><div><b>Sensibles</b><br>{'<br>'.join(groups['S']) or '—'}</div><div><b>Intermédiaires</b><br>{'<br>'.join(groups['I']) or '—'}</div><div><b>Résistants</b><br>{'<br>'.join(groups['R']) or '—'}</div></div>"
        else:
            atb="<b>Antibiogramme : Non applicable</b>"
        validateur=l.get('validator_name') or l.get('chief_validator_name') or ''
        titre=l.get('validator_title') or ''
        return f"""<div class='card printCard'><div class='reportPage'><div class='center'><b>LABORATOIRE DE BIOLOGIE MÉDICALE</b><br>Hôpital St Jean de Dieu de Boko</div><h1>RÉSULTATS D’EXAMENS BIOLOGIQUES</h1><div class='row'><div>Date du prélèvement : {h(r.get('date_prelevement'))} {h(r.get('heure_prelevement'))}</div><div>N° d’échantillon : <b>{h(r.get('sample_number'))}</b></div><div>Date de réception : {h(l.get('reception_date'))} {h(l.get('reception_time'))}</div><div>N° labo : {h(r.get('auto_number'))}</div></div><div class='row'><div>Nom et prénom : <b>{h(r.get('patient_name'))} {h(r.get('patient_firstname'))}</b></div><div>Sexe / Âge : {h(r.get('sex'))} / {h(r.get('age'))} {h(r.get('age_unit'))}</div><div>Médecin prescripteur : {h(r.get('prescriber_name'))}</div><div>Service de provenance : {h(r.get('service_prescripteur'))}</div><div>Nature du prélèvement : {h(r.get('sample_type'))}</div><div>Culture</div></div><div class='box'><div class='boxTitle'>EXAMEN MACROSCOPIQUE</div>Aspect : {h(l.get('aspect'))}</div><div class='box'><div class='boxTitle'>EXAMEN MICROSCOPIQUE</div>Leucocytes : {h(l.get('leucocytes'))} GB/ml<br>Hématies : {h(l.get('hematies'))} GR/ml<br>Cellules épithéliales : {h(l.get('cellules_epitheliales'))}<br>Autres : {h(l.get('autres_micro'))}</div><div class='box'><div class='boxTitle'>COLORATION DE GRAM</div>Résultat : {h(l.get('gram_result'))}</div><div class='box'><div class='boxTitle'>RÉSULTATS DE CULTURE ET DE L’ANTIBIOGRAMME</div>Culture : {h(culture)}<br>{h(l.get('culture_details'))}<br><br><b>Antibiogramme (EUCAST)</b><br>{atb}</div><div class='box'><div class='boxTitle'>CONCLUSION</div>{h(l.get('conclusion'))}</div><div class='sign'><b>VALIDATION</b><br><br>{h(validateur)}<br>{h(titre)}</div></div><div class='noPrint center' style='margin-top:14px'><button class='btn' onclick='print()'>Imprimer / PDF une page</button></div></div>"""
    def admin_export(self):
        u=self.require(['admin']);
        if not u:return
        content="<div class='card'><h2>Exports base type Excel</h2><p>L’administrateur peut exporter les métadonnées sans consulter les résultats médicaux détaillés.</p><a class='btn' href='/export/requests.csv'>Télécharger base demandes CSV</a></div>"
        self.send_html(layout(u,'Exports',content))
    def export_requests(self):
        u=self.require(['admin','chef_labo']);
        if not u:return
        with db_conn() as con:
            rows=con.execute("SELECT auto_number,sample_number,service_prescripteur,status,conformity,created_at,updated_at FROM requests ORDER BY id DESC").fetchall()
        self.send_csv('base_demandes_ecbu.csv', [['N° demande','N° échantillon','Service','Statut','Conformité','Création','Mise à jour']]+[list(r) for r in rows])
    def audit_page(self):
        u=self.require(['admin']);
        if not u:return
        with db_conn() as con: rows=con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500").fetchall()
        trs=''.join(f"<tr><td>{h(r['created_at'])}</td><td>{h(r['user_name'])}</td><td>{h(r['action'])}</td></tr>" for r in rows)
        self.send_html(layout(u,'Journal',f"<div class='card'><h2>Journal technique</h2><table class='table'><tr><th>Date</th><th>Utilisateur</th><th>Action</th></tr>{trs}</table></div>"))

def main():
    init_db()
    ap=argparse.ArgumentParser(); ap.add_argument('--host',default='0.0.0.0'); ap.add_argument('--port',type=int,default=int(os.environ.get('PORT',8000)))
    args=ap.parse_args()
    print(f"{APP_NAME} démarre sur http://{args.host}:{args.port}")
    print("Sur un autre PC/téléphone du même réseau: http://ADRESSE-IP-DU-SERVEUR:%s"%args.port)
    ThreadingHTTPServer((args.host,args.port),App).serve_forever()
if __name__=='__main__': main()
