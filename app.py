from flask import Flask, render_template, request, redirect, session, flash, url_for
from pymongo import MongoClient
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = "sua_chave_secreta"  # Substitua pela sua chave secreta
client = MongoClient('mongodb+srv://luanavidalnn:EhOUJpUjYvKPfQUs@cluster01.dxsxqa5.mongodb.net/')  # Atualize a URL do MongoDB, se necessário
db = client['diario_de_obras']
entries = db.entries
users = db.users  # Coleção de usuários

@app.route('/')
def index():
    if 'username' in session:
        entries_list = entries.find()
        return render_template('diary.html', entries=entries_list)
    else:
        flash('Faça login para acessar o diário.', 'danger')
        return redirect('/login')

@app.route('/add_entry', methods=['POST'])
def add_entry():
    # Verifica se o usuário está logado
    if 'username' in session:
        title = request.form.get('title')
        description = request.form.get('description')
        entry_date = request.form.get('entry_date')
        entry_time = request.form.get('entry_time')

        # Combine a data e hora em um único objeto datetime
        entry_datetime = datetime.strptime(f"{entry_date} {entry_time}", "%Y-%m-%d %H:%M")

        entries.insert_one({'title': title, 'description': description, 'entry_datetime': entry_datetime})
        return redirect('/')
    else:
        flash('Faça login para adicionar uma entrada.', 'danger')
        return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        
        if users.find_one({'username': username}):
            flash('Nome de usuário já existe.', 'danger')
        else:
            users.insert_one({'username': username, 'password': hashed_password})
            flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
            return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        
        user = users.find_one({'username': username})
        
        if user and bcrypt.checkpw(password, user['password']):
            session['username'] = username
            flash('Login bem-sucedido!', 'success')
            return redirect('/')
        else:
            flash('Credenciais inválidas. Tente novamente.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Você foi desconectado.', 'info')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
