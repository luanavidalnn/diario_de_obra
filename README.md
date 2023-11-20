# diario_de_obra
## clone o repositório
git clone <link repo>
## certifique-se que esta na branch main
git checkout main
## certifique-se que não tem processos python rodando na porta 5000 para não dar conflito
sudo netstat -tuln | grep 5000
## se tiver execute:
sudo killall -9 python 
## acesse o diretorio "diario_de_obra" e execute:
python app.py
## abra a o localhost na porta 5000 pelo navegador:
127.0.0.1:5000
## acesso admin
login: admin
senha: 12345
=======
## rode o app
python app.py

