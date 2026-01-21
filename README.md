source .venv/bin/activate
pip install flask flask-sqlalchemy flask-login python-dotenv psycopg2-binary
pip freeze > requirements.txt

python app.py