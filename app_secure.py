import bcrypt
import sqlite3
import os
import secrets
import re
import html
from datetime import datetime, timedelta
from flask import Flask, request, session, redirect, url_for

app = Flask(__name__)

app.secret_key = os.urandom(24)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=600 
)

def get_db():
    conn = sqlite3.connect('deskly.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_action(user_id, action, resource, resource_id=None):
    db = get_db()
    db.execute("INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)",
               (user_id, action, resource, resource_id, request.remote_addr))
    db.commit()


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    return '''
        <div style="font-family: sans-serif; display: flex; justify-content: space-around; margin-top: 50px;">
            <div style="border: 1px solid #ccc; padding: 20px; border-radius: 10px; width: 320px;">
                <h2>Login (v2)</h2>
                <form action="/login" method="post">
                    Email:<br> <input type="text" name="email" style="width:100%"><br><br>
                    Parolă:<br> <input type="password" name="password" style="width:100%"><br><br>
                    <input type="submit" value="Autentificare" style="width:100%; cursor:pointer;">
                </form>
                <br><center><a href="/forgot_password">Am uitat parola</a></center>
            </div>
            <div style="border: 1px solid #ccc; padding: 20px; border-radius: 10px; width: 320px;">
                <h2>Register (v2)</h2>
                <form action="/register" method="post">
                    Email:<br> <input type="text" name="email" style="width:100%"><br><br>
                    Parolă:<br> <input type="password" name="password" style="width:100%"><br>
                    <small style="color: gray;">Minim 8 caractere, litere și cifre [cite: 65]</small><br><br>
                    <input type="submit" value="Creează Cont" style="width:100%; cursor:pointer;">
                </form>
            </div>
        </div>
    '''


@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    
   
    if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Eroare: Format email invalid! <br><br><a href='/'>Înapoi la Login</a>"
    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[a-zA-Z]", password):
        return "Eroare: Parola nu respectă politica de complexitate! <br><br><a href='/'>Înapoi la Login</a>"
        
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    try:
        db = get_db()
        cursor = db.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", 
                            (email, hashed_pw, 'ANALYST'))
        db.commit()
        log_action(cursor.lastrowid, 'REGISTER', 'auth', cursor.lastrowid)
        return "Cont creat cu succes! <br><br><a href='/'>Mergi la Login</a>"
    except sqlite3.IntegrityError:
        return "Eroare: Email-ul există deja! <br><br><a href='/'>Înapoi</a>"

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '')
    password = request.form.get('password', '').encode('utf-8')
    db = get_db()
    
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    
    error_msg = "Email sau parolă incorectă! <br><br><a href='/'>Înapoi</a>"
    
    if user:
        if user['locked']:
            log_action(user['id'], 'LOGIN_BLOCKED', 'auth')
            return "Cont blocat din motive de securitate. Contactați un administrator. <br><br><a href='/'>Înapoi</a>"

        if bcrypt.checkpw(password, user['password_hash'].encode('utf-8')):
            db.execute("UPDATE users SET login_attemps = 0 WHERE id = ?", (user['id'],))
            db.commit()
            
            session.update({'user_id': user['id'], 'role': user['role'], 'email': email})
            log_action(user['id'], 'LOGIN_SUCCESS', 'auth')
            return redirect(url_for('dashboard'))
        else:

            attempts = user['login_attemps'] + 1
            db.execute("UPDATE users SET login_attemps = ?, locked = ? WHERE id = ?", (attempts, attempts >= 5, user['id']))
            db.commit()
            log_action(user['id'], 'LOGIN_FAILED', 'auth')
            
    return error_msg


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        
        msg = "Dacă adresa există, un link de resetare a fost trimis. <br><br><a href='/'>Înapoi la Login</a>"
        
        if user:
            token = secrets.token_urlsafe(32)
            expiry = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')
            db.execute("UPDATE users SET reset_token = ?, token_expiry = ? WHERE id = ?", (token, expiry, user['id']))
            db.commit()
            log_action(user['id'], 'PASSWORD_RESET_REQUESTED', 'auth')
            msg += f'<hr><b>Link Demo (PoC):</b> <a href="/reset_password/{token}">/reset_password/{token}</a>'
            
        return f'<div style="font-family:sans-serif; padding:20px;">{msg}</div>'
        
    return '''
        <div style="font-family:sans-serif; padding:50px;">
            <h2>Resetare Parolă</h2>
            <form method="post">
                Introduceți Email-ul: <input type="text" name="email" required>
                <input type="submit" value="Trimite Link">
            </form>
            <br><a href="/">← Înapoi la Login</a>
        </div>
    '''

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ? AND token_expiry > CURRENT_TIMESTAMP", (token,)).fetchone()
    
    if not user: return "Link de resetare invalid sau expirat! <br><br><a href='/'>Înapoi</a>"
        
    if request.method == 'POST':
        pw = request.form.get('password')
        if len(pw) < 8 or not re.search(r"\d", pw): return "Parola nouă este prea slabă!"
            
        hashed = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.execute("UPDATE users SET password_hash = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?", (hashed, user['id']))
        db.commit()
        log_action(user['id'], 'PASSWORD_RESET_SUCCESS', 'auth')
        return "Parolă schimbată! <a href='/'>Logați-vă aici</a>"
        
    return '''
        <div style="font-family:sans-serif; padding:50px;">
            <h2>Setați Parola Nouă</h2>
            <form method="post">
                Noua Parolă: <input type="password" name="password" required>
                <input type="submit" value="Actualizează">
            </form>
            <br><a href="/">Anulează și mergi la Login</a>
        </div>
    '''


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('index'))
    safe_email = html.escape(session['email'])
    return f'''
        <div style="font-family: sans-serif; padding: 50px;">
            <h1>Dashboard Deskly</h1>
            <p>Bun venit, <b>{safe_email}</b>! Rol: <i>{session['role']}</i></p>
            <hr>
            <nav>
                <a href="/tickets"><button style="padding:10px; cursor:pointer;">Gestionează Tichete</button></a> 
                <a href="/logout"><button style="padding:10px; cursor:pointer;">Logout (Ieșire)</button></a>
            </nav>
        </div>
    '''

@app.route('/tickets', methods=['GET', 'POST'])
def tickets():
    if 'user_id' not in session: return redirect(url_for('index'))
    db = get_db()
    
    if request.method == 'POST' and 'create' in request.form:
        db.execute("INSERT INTO tickets (title, description, owner_id) VALUES (?, ?, ?)",
                   (request.form['title'], request.form['description'], session['user_id']))
        db.commit()
        log_action(session['user_id'], 'CREATE_TICKET', 'tickets')

    if session['role'] == 'MANAGER':
        tickets_list = db.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
    else:
        tickets_list = db.execute("SELECT * FROM tickets WHERE owner_id = ? ORDER BY created_at DESC", (session['user_id'],)).fetchall()

    rows = ""
    for t in tickets_list:
        rows += f"""<tr>
            <td>{t['id']}</td>
            <td>{html.escape(t['title'])}</td>
            <td>{t['status']}</td>
            <td><a href='/edit_ticket/{t['id']}'>Editare</a></td>
        </tr>"""

    return f'''
        <div style="font-family: sans-serif; padding: 50px;">
            <a href="/dashboard">← Înapoi la Dashboard</a>
            <h2>Tichetele Mele</h2>
            
            <div style="border: 1px solid #ddd; padding: 15px; background: #f9f9f9; width: 400px;">
                <h4>Adaugă Tichet Nou</h4>
                <form method="post"><input type="hidden" name="create">
                    Titlu: <br><input type="text" name="title" required style="width:100%"><br><br>
                    Descriere: <br><input type="text" name="description" style="width:100%"><br><br>
                    <input type="submit" value="Salvează Tichet">
                </form>
            </div>

            <table border="1" style="width:100%; margin-top:20px; border-collapse:collapse;">
                <tr style="background:#eee;"><th>ID</th><th>Titlu</th><th>Status</th><th>Acțiuni</th></tr>
                {rows}
            </table>
        </div>
    '''

@app.route('/edit_ticket/<int:id>', methods=['GET', 'POST'])
def edit_ticket(id):
    if 'user_id' not in session: return redirect(url_for('index'))
    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (id,)).fetchone()
    
    if not ticket: return "Eroare: Tichet negăsit! <br><br><a href='/tickets'>Înapoi</a>"
    
    if session['role'] != 'MANAGER' and ticket['owner_id'] != session['user_id']:
        log_action(session['user_id'], 'UNAUTHORIZED_ACCESS_ATTEMPT', 'tickets', id)
        return "<b>Acces Interzis!</b> Nu poți edita un tichet care nu îți aparține. <br><br><a href='/tickets'>Înapoi</a>"

    if request.method == 'POST':
        db.execute("UPDATE tickets SET title = ?, description = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                   (request.form['title'], request.form['description'], request.form['status'], id))
        db.commit()
        log_action(session['user_id'], 'EDIT_TICKET', 'tickets', id)
        return redirect(url_for('tickets'))

    return f'''
        <div style="font-family:sans-serif; padding:50px;">
            <a href="/tickets">← Înapoi la Lista de Tichete</a>
            <h2>Editare Tichet #{id}</h2>
            <form method="post">
                Titlu: <br><input type="text" name="title" value="{html.escape(ticket['title'])}" style="width:300px;"><br><br>
                Descriere: <br><textarea name="description" style="width:300px;">{html.escape(ticket['description'])}</textarea><br><br>
                Status: <br>
                <select name="status">
                    <option value="OPEN" {"selected" if ticket['status']=='OPEN' else ""}>OPEN</option>
                    <option value="IN_PROGRESS" {"selected" if ticket['status']=='IN_PROGRESS' else ""}>IN PROGRESS</option>
                    <option value="RESOLVED" {"selected" if ticket['status']=='RESOLVED' else ""}>RESOLVED</option>
                </select><br><br>
                <input type="submit" value="Actualizează Tichet" style="padding:10px; cursor:pointer;">
            </form>
        </div>
    '''

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'LOGOUT', 'auth')
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
