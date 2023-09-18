# diario_de_obra
## clone o repositório
git clone <link repo>
## certifique-se que esta na branch development
git checkout development
## certifique-se que não tem processos python rodando na porta 5000 para não dar conflito
sudo netstat -tuln | grep 5000
## se tiver execute:
sudo killall -9 python 
## acesse o diretorio "diario_de_obra" e execute:
python app.py
## abra a o localhost na porta 5000 pelo navegador:
127.0.0.1:5000