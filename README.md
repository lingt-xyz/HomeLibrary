python3 -m venv .venv

source .venv/bin/activate
pip install flask flask-sqlalchemy flask-login python-dotenv psycopg2-binary Flask-Mail pytz
pip freeze > requirements.txt

pip install -r requirements.txt

python app.py
