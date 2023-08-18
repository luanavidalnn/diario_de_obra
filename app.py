from flask import Flask, render_template, request, redirect
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient('mongodb+srv://m001-student:0I0RRQtv0BV4bqAf@sandbox.16ijx.mongodb.net/?retryWrites=true&w=majority')  # Atualize a URL do MongoDB, se necessário
db = client['diario_de_obras']
entries = db.entries

@app.route('/')
def index():
    return render_template('diary.html', entries=entries.find())

@app.route('/add_entry', methods=['POST'])
def add_entry():
    title = request.form.get('title')
    description = request.form.get('description')
    entries.insert_one({'title': title, 'description': description})
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
