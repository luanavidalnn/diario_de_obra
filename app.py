from flask import Flask, render_template, request, redirect, session, flash
from pymongo import MongoClient
import bcrypt
from datetime import datetime
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = "sua_chave_secreta"
client = MongoClient('mongodb+srv://luanavidalnn:Uu5XcplTXslu5YZE@cluster01.dxsxqa5.mongodb.net/'
                    '?retryWrites=true&w=majority')
db = client['diario_de_obras']
entries = db.entries
users = db.users
works = db.works

def is_admin():
    if 'username' in session:
        username = session['username']
        user = users.find_one({'username': username})
        return user.get('profile') == 'administrador'
    return False

@app.before_request
def require_login():
    allowed_routes = ['login', 'register']
    if request.endpoint not in allowed_routes and 'username' not in session:
        flash('Faça login para acessar esta página.', 'danger')
        return redirect('/login')

@app.route('/')
def index():
    username = session['username']
    entries_list = entries.find({'created_by': username})
    return render_template('diary.html', entries=entries_list)

@app.route('/add_entry', methods=['POST'])
def add_entry():
    if 'username' in session:
        username = session['username']
        title = request.form.get('title')
        description = request.form.get('description')
        entry_date = request.form.get('entry_date')
        entry_time = request.form.get('entry_time')

        entry_datetime = datetime.strptime(f"{entry_date} {entry_time}", "%Y-%m-%d %H:%M")

        entries.insert_one({'title': title, 'description': description, 'entry_datetime': entry_datetime, 'created_by': username})
        flash('Entrada adicionada com sucesso!', 'success')
        return redirect('/')
    else:
        flash('Faça login para adicionar uma entrada.', 'danger')
        return redirect('/login')

@app.route('/users', methods=['POST'])
def add_user():
    if is_admin():
        # Adicione o usuário
        return redirect('/users')

# Editar um usuário
@app.route('/users/<username>', methods=['PUT'])
def edit_user(username):
    if is_admin():
        # Atualize o usuário
        return redirect('/users')

# Remover um usuário
@app.route('/users/<username>', methods=['DELETE'])
def delete_user(username):
    if is_admin():
        # Remova o usuário
        return redirect('/users')


@app.route('/report/works')
def report_works():
    works_list = works.find()
    return render_template('report_works.html', works=works_list)

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

@app.route('/manage_users')
def manage_users():
    print("Acessou a rota de gerenciamento de usuarios")
    if is_admin():
        users_list = users.find()
        return render_template('manage_users.html', users=users_list)
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')

@app.route('/manage_works')
def manage_works():
    if is_admin():
        works_list = works.find()
        return render_template('works_list.html', works=works_list)
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')
    
@app.route('/works')
def list_works():
    if 'username' in session:
        username = session['username']
        user = users.find_one({'username': username})

        if user.get('profile') == 'admin':
            # Consulte as obras no banco de dados e passe-as para o modelo
            works_list = works.find()
            return render_template('works_list.html', works=works_list)
        else:
            flash('Acesso permitido apenas para o administrador.', 'danger')
            return redirect('/')
    else:
        flash('Faça login para acessar esta página.', 'danger')
        return redirect('/login')

@app.route('/works/add', methods=['POST'])
def add_work():
    if is_admin():
        work_name = request.form.get('work_name')
        works.insert_one({'work_name': work_name})
        flash('Obra cadastrada com sucesso!', 'success')
        return redirect('/works')
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')
    
@app.route('/works/edit/<work_id>', methods=['POST'])
def edit_work(work_id):
    if is_admin():
        new_work_name = request.form.get('new_work_name')
        works.update_one({'_id': ObjectId(work_id)}, {"$set": {'work_name': new_work_name}})
        flash('Obra atualizada com sucesso!', 'success')
        return redirect('/works')
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')
    
@app.route('/works/delete/<work_id>')
def delete_work(work_id):
    if is_admin():
        works.delete_one({'_id': ObjectId(work_id)})
        flash('Obra excluída com sucesso!', 'success')
        return redirect('/works')
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')

@app.route('/report')
def report():
    if is_admin():
        entries_list = entries.find()
        return render_template('report.html', entries=entries_list)
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')


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
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
