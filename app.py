import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv

# Important for Vercel: Set instance_path to /tmp to avoid the Read-only error
app = Flask(__name__, instance_path='/tmp')

# Load variables from .env into the system environment
load_dotenv()

# Check if we are on Vercel or have a DATABASE_URL set
# If not, fall back to local SQLite for development
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Fix for SQLAlchemy 1.4+ which requires "postgresql://" not "postgres://"
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'

# Fetch the key from the environment
# If the .env file is missing, it uses a fallback 'dev-secret' for safety
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-123')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    
    # ADD THIS: If a user is deleted, their comments/interactions are deleted too
    interactions = db.relationship('ReaderInteraction', backref='user', cascade="all, delete-orphan")

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    
    # ADD THIS: If a book is deleted, all comments tied to that book are deleted too
    interactions = db.relationship('ReaderInteraction', backref='book', cascade="all, delete-orphan")

class ReaderInteraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # The ForeignKey stays the same
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    comment = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.now)

# --- Security Decorators ---

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash("You do not have permission to access this page.", "warning")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            if user.role == 'admin': return redirect(url_for('admin_dashboard'))
            if user.role == 'librarian': return redirect(url_for('librarian_dashboard'))
            return redirect(url_for('reader_dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Admin: Add Librarians and Readers
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_dashboard():
    if request.method == 'POST':
        username = request.form.get('username')
        # SCRAMBLE the password before it ever touches the database
        raw_password = request.form.get('password')
        hashed_password = generate_password_hash(raw_password, method='pbkdf2:sha256')
        role = request.form.get('role')
        # Prevent duplicate usernames
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
        else:
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {username} created as {role}!", "success")
    # Fetch all users to display them in the list
    all_users = User.query.all() 
    return render_template('admin.html', users=all_users)

@app.route('/delete_user/<int:user_id>')
@login_required
@role_required('admin')
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    
    # Security check: Prevent admin from deleting their own account
    if user_to_delete.id == current_user.id:
        flash("You cannot delete your own admin account!", "danger")
        return redirect(url_for('admin_dashboard'))
    
    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f"User {user_to_delete.username} has been deleted.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/librarian', methods=['GET', 'POST'])
@login_required
@role_required('librarian')
def librarian_dashboard():
    # Logic for adding books (as before)
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        new_book = Book(title=title, author=author)
        db.session.add(new_book)
        db.session.commit()
        flash("New book added to library.", "success")

    # Data for the page
    books = Book.query.all()
    
    # Fetch all reader interactions, ordered by the most recent
    all_interactions = ReaderInteraction.query.order_by(ReaderInteraction.id.desc()).all()
    
    return render_template('librarian.html', books=books, interactions=all_interactions)

@app.route('/delete_book/<int:id>')
@login_required
@role_required('librarian')
def delete_book(id):
    book = Book.query.get(id)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('librarian_dashboard'))

@app.route('/reader', methods=['GET', 'POST'])
@login_required
@role_required('reader')
def reader_dashboard():
    # 1. Handle New Book Submission with Validation
    if request.method == 'POST' and 'title' in request.form:
        # SANITIZATION: Remove leading/trailing spaces and force Title Case
        raw_title = request.form.get('title', '').strip()
        raw_author = request.form.get('author', '').strip()

        # Convert to Title Case (e.g., "the GREAT gatsby" -> "The Great Gatsby")
        title = raw_title.title()
        author = raw_author.title()

        if not title or not author:
            flash("Error: Book title and author cannot be empty.", "danger")
            return redirect(url_for('reader_dashboard'))

        # Validation Check: Case-insensitive search for Title AND Author
        existing_book = Book.query.filter(
            Book.title.ilike(title),
            Book.author.ilike(author)
        ).first()

        if existing_book:
            # If the book exists, send an error and don't save
            flash(f"Error: '{title}' by {author} already exists in the library.", "danger")
        else:
            # If the book is new, save it
            new_book = Book(title=title, author=author)
            db.session.add(new_book)
            db.session.commit()
            flash(f"Successfully added '{title}' to the library.", "success")
        
        # Always redirect to prevent form resubmission on page refresh
        return redirect(url_for('reader_dashboard'))

    # 2. Search and Pagination Logic (continues as before)
    search_query = request.args.get('q', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    query = Book.query
    if search_query:
        query = query.filter(
            (Book.title.contains(search_query)) | 
            (Book.author.contains(search_query))
        )

    pagination = query.paginate(page=page, per_page=per_page)
    # Total count for the user
    total_results = pagination.total

    interactions = ReaderInteraction.query.filter_by(user_id=current_user.id).all()
    user_comments = {i.book_id: i.comment for i in interactions}
    history = ReaderInteraction.query.filter_by(user_id=current_user.id).order_by(ReaderInteraction.timestamp.desc()).all()
    stats = get_reader_stats(current_user.id)
    return render_template('reader.html',
                           stats=stats, 
                           pagination=pagination, 
                           total_results=total_results, 
                           history=history,
                           user_comments=user_comments,
                           search_query=search_query)

@app.route('/reader/comment/<int:book_id>', methods=['POST'])
@login_required
@role_required('reader')
def add_comment(book_id):
    comment = request.form.get('comment', '').strip()

    if not comment:
        flash("You must write a comment to mark this book as read!", "warning")
        return redirect(url_for('reader_dashboard'))
        
    # 1. Search for an existing interaction for this user and this book
    existing_interaction = ReaderInteraction.query.filter_by(
        user_id=current_user.id, 
        book_id=book_id
    ).first()

    if existing_interaction:
        # 2. UPDATE: If it exists, change the comment and time
        existing_interaction.comment = comment
        existing_interaction.timestamp = datetime.now()
        flash("Your review for this book has been updated.", "success")
    else:
        # 3. CREATE: If it doesn't exist, make a new record
        new_interaction = ReaderInteraction(
            user_id=current_user.id, 
            book_id=book_id, 
            comment=comment
        )
        db.session.add(new_interaction)

        new_count = ReaderInteraction.query.filter_by(user_id=current_user.id).count()
        if new_count == 1:
            flash("Congratulations! You've started your reading journey! 🌟", "success")
        elif new_count == 5:
            flash("Level Up! You are now an 'Active Reader'! 📚", "success")
        elif new_count == 20:
            flash("UNLOCKED: Master Scholar Rank! 🏆", "milestone")
        else:
            flash("Review submitted successfully!", "success")

    db.session.commit()
    return redirect(url_for('reader_dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_username = request.form.get('username').strip()
        new_password = request.form.get('password')
        
        # Check if the new username is already taken by someone else
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user and existing_user.id != current_user.id:
            flash("Error: That username is already taken.", "danger")
            return redirect(url_for('profile'))

        # Update Username
        if new_username:
            current_user.username = new_username
        
        # Update Password (if provided)
        if new_password:
            current_user.password = generate_password_hash(new_password)
            
        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))
        
    return render_template('profile.html')

def get_reader_stats(user_id):
    # Count how many unique books the user has reviewed
    total_read = ReaderInteraction.query.filter_by(user_id=user_id).count()
    
    # Determine Rank
    if total_read >= 100:
        rank, color, next_m = "Library Legend", "text-dark", 200
    elif total_read >= 50:
        rank, color, next_m = "Grand Librarian", "text-info", 100
    elif total_read >= 20:
        rank = "Master Scholar"
        color = "text-danger"
        next_milestone = 50
    elif total_read >= 10:
        rank = "Bookworm"
        color = "text-success"
        next_milestone = 20
    elif total_read >= 5:
        rank = "Active Reader"
        color = "text-primary"
        next_milestone = 10
    else:
        rank = "Novice"
        color = "text-secondary"
        next_milestone = 5
        
    # Calculate progress percentage toward the next milestone
    progress = (total_read / next_milestone) * 100
    
    return {
        "count": total_read,
        "rank": rank,
        "color": color,
        "progress": min(progress, 100),
        "next": next_milestone
    }

# --- Initialization ---

if __name__ == '__main__':
    with app.app_context():
        # db.create_all()
        # Create a default admin if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=generate_password_hash('admin123'), role='admin')
            db.session.add(admin)
            db.session.commit()
    app.run(debug=os.environ.get('DEBUG'))

@app.route('/init-db')
def init_db():
    with app.app_context():
        db.create_all()
    return "Database tables created successfully!"
