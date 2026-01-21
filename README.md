source .venv/bin/activate
pip install flask flask-sqlalchemy flask-login python-dotenv
pip freeze > requirements.txt

python app.py