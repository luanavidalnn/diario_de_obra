import bson
import bson.errors
from flask import Flask, render_template, request, redirect, session, flash, jsonify
from pymongo import MongoClient
import bcrypt
from datetime import datetime
from bson import ObjectId
import logging

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = "sua_chave_secreta"
client = MongoClient('mongodb+srv://luanavidalnn:Uu5XcplTXslu5YZE@cluster01.dxsxqa5.mongodb.net/'
                    '?retryWrites=true&w=majority')
db = client['diario_de_obras']
entries = db.entries
users = db.users
works = db.works
users_list = []
works_list = []


def is_admin_user():
    if 'username' in session:
        username = session['username']
        user = users.find_one({'username': username})
        return user.get('profile') == 'administrador'
    return False

def is_valid_object_id(value):
    try:
        ObjectId(value)
        return True
    except (InvalidId, ValueError, TypeError):
        return False

@app.context_processor
def utility_processor():
    return dict(is_admin_user=is_admin_user)


@app.before_request
def require_login():
    allowed_routes = ['login', 'register']
    if request.endpoint not in allowed_routes and 'username' not in session:
        flash('Faça login para acessar esta página.', 'danger')
        return redirect('/login')

@app.route('/')
def index():
    username = session['username']
    is_admin = is_admin_user()  
    entries_list = entries.find({'created_by': username})
    return render_template('diary.html', entries=entries_list, is_admin=is_admin)



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
    if is_admin_user():
        users_list = list(users.find({}, {'_id': 0}))
        return render_template('manage_users.html', users=users_list)
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')

@app.route('/get_users')
def get_users():
    users_list = list(users.find({}, {'_id': 0}))
    for user in users_list:
        if 'password' in user:
            user['password'] = user['password'].decode('utf-8')
    return jsonify(users_list)

@app.route('/users/add', methods=['POST'])
def add_user():
    if is_admin_user():
        username = request.form.get('username')
        profile = request.form.get('profile')
        password = request.form.get('password').encode('utf-8')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        if users.find_one({'username': username}):
            return jsonify({'success': False, 'message': 'Nome de usuário já existe.'})
        else:
            users.insert_one({'username': username, 'profile': profile, 'password': hashed_password})
            return jsonify({'success': True, 'message': 'Usuário cadastrado com sucesso!'})
    else:
        return jsonify({'success': False, 'message': 'Acesso permitido apenas para o administrador.'})
    
@app.route('/edit_user/<username>')
def edit_user(username):
    if is_admin_user():
        user_details = {'username': username, 'profile': ''}
        return render_template('edit_user.html', user=user_details)
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/manage_users')
    
@app.route('/update_user', methods=['POST'])
def update_user():
    if is_admin_user():
        username = request.form.get('username')
        profile = request.form.get('profile')      
        users.update_one({'username': username}, {"$set": {'profile': profile}})
        return jsonify({'success': True, 'message': 'Usuário atualizado com sucesso!'})
    else:
        return jsonify({'success': False, 'message': 'Acesso permitido apenas para o administrador.'})

@app.route('/remove_user/<username>', methods=['POST'])
def remove_user(username):
    if is_admin_user():
        users.delete_one({'username': username})
        return jsonify({'success': True, 'message': f'Usuário {username} removido com sucesso!'})
    else:
        return jsonify({'success': False, 'message': 'Acesso permitido apenas para o administrador.'})


@app.route('/manage_works')
def manage_works():
    if is_admin_user():
        works_list = list(works.find({}, {'_id': 0}))
        return render_template('manage_works.html', works=works_list)
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')


@app.route('/add_works', methods=['GET', 'POST'])
def add_works():
    if request.method == 'POST':
        if is_admin_user():
            work_name = request.form.get('work_name')
            if works.find_one({'work_name': work_name}):
                return jsonify({'success': False, 'message': 'Nome de obra já existe.'})
            else:
                works.insert_one({'work_name': work_name})
                return jsonify({'success': True, 'message': 'Obra cadastrada com sucesso!'})

    return render_template('add_works.html')

@app.route('/get_works')
def get_works():
    works_list = list(works.find({}, {'_id': 1, 'work_name': 1}))
    for work in works_list:
        work['_id'] = str(work['_id'])
    return jsonify(works_list)

@app.route('/edit_works/<work_name>', methods=['GET', 'POST'])
def edit_works(work_name):
    if is_admin_user():
        work_details = works.find_one({'work_name': work_name})
        
        if work_details:
            if request.method == 'POST':
                new_work_name = request.form.get('new_work_name')
                works.update_one({'work_name': work_name}, {"$set": {'work_name': new_work_name}})
                flash('Obra atualizada com sucesso!', 'success')
                return redirect('/manage_works')
            else:
                return render_template('edit_works.html', works=work_details)
        else:
            flash('Obra não encontrada', 'danger')
            return redirect('/manage_works')
    else:
        flash('Acesso permitido apenas para o administrador.', 'danger')
        return redirect('/')
    
@app.route('/remove_works/<work_name>', methods=['POST'])
def remove_works(work_name):
    if is_admin_user():
        works.delete_one({'work_name': work_name})
        return jsonify({'success': True, 'message': 'Obra removida com sucesso!'})
    else:
        return jsonify({'success': False, 'message': 'Acesso permitido apenas para o administrador.'})
   
@app.route('/update_work', methods=['POST'])
def update_work():
    if is_admin_user():
        work_name = request.form.get('work_name')    
        works.update_one({'_id': ObjectId(work_id)}, {"$set": {'work_name': work_name}})
        return jsonify({'success': True, 'message': 'Obra atualizada com sucesso!'})
    else:
        return jsonify({'success': False, 'message': 'Acesso permitido apenas para o administrador.'})

@app.route('/report')
def report():
    if is_admin_user():
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
