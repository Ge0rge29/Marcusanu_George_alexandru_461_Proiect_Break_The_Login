from flask import Flask, request, render_template_string, redirect, make_response
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('deskly_v1.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    user_email = request.cookies.get('user_session')
    if user_email:
        return redirect('/dashboard')

    return '''
        <div style="font-family: sans-serif; display: flex; justify-content: space-around; margin-top: 50px;">
            <div style="border: 1px solid red; padding: 20px; width: 300px; background: #fff0f0;">
                <h2 style="color: red;">Login (VULNERABIL)</h2>
                <form action="/login" method="post">
                    Email:<br> <input type="text" name="email"><br><br>
                    Parolă:<br> <input type="password" name="password"><br><br>
                    <input type="submit" value="Login">
                </form>
                <br><a href="/forgot_password">Am uitat parola</a>
            </div>
            <div style="border: 1px solid red; padding: 20px; width: 300px; background: #fff0f0;">
                <h2 style="color: red;">Register (VULNERABIL)</h2>
                <form action="/register" method="post">
                    Email:<br> <input type="text" name="email"><br><br>
                    Parolă:<br> <input type="password" name="password"><br><br>
                    <input type="submit" value="Register">
                </form>
            </div>
        </div>
    '''

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')

    db = get_db()
    query = f"INSERT INTO users (email, password_hash) VALUES ('{email}', '{password}')"
    try:
        db.executescript(query)
        db.commit()
        return "Cont creat cu succes! <a href='/'>Login</a>"
    except Exception as e:
        return f"Eroare DB: {str(e)}" # Information Disclosure (Stack Trace)

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    db = get_db()
    query = f"SELECT * FROM users WHERE email = '{email}'"
    user = db.execute(query).fetchone()

    if not user:
        return "Utilizatorul nu există în sistem! <a href='/'>Înapoi</a>"
    
    if user['password_hash'] != password:
        return "Parola este greșită! Mai încearcă. <a href='/'>Înapoi</a>"

    resp = make_response(redirect('/dashboard'))
    resp.set_cookie('user_session', email) 
    resp.set_cookie('user_role', user['role']) 
    return resp

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('user_session')
    resp.delete_cookie('user_role')
    return resp

# --- VULNERABILITATE 4.6: Token predictibil și reutilizabil ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        db = get_db()
        token = email 
        db.execute(f"UPDATE users SET reset_token = '{token}' WHERE email = '{email}'")
        db.commit()
        
        return f"Dacă mailul e corect, folosește acest link: <a href='/reset_password/{token}'>Reset</a>"
        
    return '<form method="post">Email-ul tău: <input type="text" name="email"><input type="submit"></form>'

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    user = db.execute(f"SELECT * FROM users WHERE reset_token = '{token}'").fetchone()
    
    if not user:
        return "Token invalid!"
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        db.execute(f"UPDATE users SET password_hash = '{new_password}' WHERE id = {user['id']}")
        db.commit()
        return "Parola a fost schimbată! <a href='/'>Login</a>"
        
    return '<form method="post">Noua Parolă: <input type="password" name="password"><input type="submit"></form>'

@app.route('/dashboard')
def dashboard():
    user_email = request.cookies.get('user_session')
    user_role = request.cookies.get('user_role')
    
    if not user_email:
        return redirect('/')
        
    return f'''
        <div style="font-family: sans-serif; padding: 50px;">
            <h2>Dashboard (VULNERABIL)</h2>
            <p>Conectat ca: {user_email} (Rol: {user_role})</p>
            <a href="/tickets">Gestionează Tichete</a> | <a href="/logout">Logout</a>
        </div>
    '''

@app.route('/tickets', methods=['GET', 'POST'])
def tickets():
    user_email = request.cookies.get('user_session')
    if not user_email: return redirect('/')
    
    db = get_db()
    
    if request.method == 'POST':
        title = request.form.get('title')
        desc = request.form.get('description')
        db.executescript(f"INSERT INTO tickets (title, description, severity) VALUES ('{title}', '{desc}', 'LOW')")
        db.commit()

    search = request.args.get('q', '')
    if search:
        tickets = db.execute(f"SELECT * FROM tickets WHERE title LIKE '%{search}%'").fetchall()
        header = f"<h3>Rezultate pentru: {search}</h3>" 
    else:
        tickets = db.execute("SELECT * FROM tickets").fetchall()
        header = "<h3>Toate tichetele</h3>"

    rows = ""
    for t in tickets:
        rows += f"<tr><td>{t['id']}</td><td>{t['title']}</td><td>{t['description']}</td><td><a href='/edit_ticket/{t['id']}'>Edit (IDOR)</a></td></tr>"

    return f'''
        <div style="font-family: sans-serif; padding: 50px;">
            <h2>Tichete</h2>
            <form method="get">
                Caută: <input type="text" name="q" value="{search}">
                <input type="submit" value="Caută">
            </form>
            <br>
            <form method="post">
                Creare tichet - Titlu: <input type="text" name="title">
                Descriere: <input type="text" name="description">
                <input type="submit" value="Adaugă">
            </form>
            {header}
            <table border="1">
                <tr><th>ID</th><th>Titlu</th><th>Descriere</th><th>Acțiuni</th></tr>
                {rows}
            </table>
            <br><a href="/dashboard">Back</a>
        </div>
    '''

@app.route('/edit_ticket/<id>', methods=['GET', 'POST'])
def edit_ticket(id):
    db = get_db()
    
    if request.method == 'POST':
        new_desc = request.form.get('description')
        db.execute(f"UPDATE tickets SET description = '{new_desc}' WHERE id = {id}")
        db.commit()
        return redirect('/tickets')
        
    ticket = db.execute(f"SELECT * FROM tickets WHERE id = {id}").fetchone()
    if not ticket: return "Nu există"
    
    return f'''
        <div style="font-family:sans-serif; padding:50px;">
            <h3>Editare Tichet {id}</h3>
            <form method="post">
                Descriere: <input type="text" name="description" value="{ticket['description']}">
                <input type="submit" value="Modifică">
            </form>
        </div>
    '''

if __name__ == '__main__':
    app.run(debug=True, port=5001)
