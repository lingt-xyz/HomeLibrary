import os
from datetime import date, datetime, timedelta, timezone
import pytz
import secrets
from flask import Flask, render_template, redirect, url_for, request, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF
from sqlalchemy import func
from functools import wraps
from dotenv import load_dotenv
from flask_mail import Mail, Message

# Important for Vercel: Set instance_path to /tmp to avoid the Read-only error
app = Flask(__name__, instance_path='/tmp')

# Load variables from .env into the system environment
load_dotenv()

# Looking to send emails in production? Check out our Email API/SMTP product!
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

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
# Set remember me cookie to expire after 30 days
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='reader')

    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    password_last_changed = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)

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
    return db.session.get(User, int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Check if the "remember" checkbox was ticked
        remember_me = True if request.form.get('remember') else False
        user = User.query.filter_by(username=username).first()

        if user:
            # 1. Check if the user is currently locked out
            if user.lockout_until and user.lockout_until > datetime.now(timezone.utc):
                time_left = (user.lockout_until - datetime.now(timezone.utc)).seconds // 60
                flash(f"Account locked. Try again in {max(1, time_left)} minutes.", "danger")
                return redirect(url_for('login'))

            # 2. Check the password
            if check_password_hash(user.password, password):
                # SUCCESS: Reset attempts and lockout
                user.failed_login_attempts = 0
                user.lockout_until = None
                db.session.commit()
                login_user(user, remember=remember_me)
                if user.role == 'admin': return redirect(url_for('admin_dashboard'))
                if user.role == 'librarian': return redirect(url_for('librarian_dashboard'))
                return redirect(url_for('reader_dashboard'))
            else:
                # FAILURE: Increment counter
                user.failed_login_attempts += 1
                
                if user.failed_login_attempts >= 5:
                    # Lock the account for 10 minutes
                    user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=10)
                    flash("Too many failed attempts. Account locked for 10 minutes.", "danger")
                else:
                    attempts_left = 5 - user.failed_login_attempts
                    flash(f"Invalid password. {attempts_left} attempts remaining.", "warning")
                
                db.session.commit()
        else:
            flash("User not found.", "danger")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_input = request.form.get('email')
        user = User.query.filter_by(email=email_input).first()

        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.token_expiry = datetime.now(timezone.utc) + timedelta(minutes=30)
            db.session.commit()

            # Generate the URL
            reset_url = url_for('reset_with_token', token=token, _external=True)
            
            # Create the Message object
            msg = Message("Reset Your Home Library Password",
                          sender="noreply@homelibrary.com",
                          recipients=[user.email])
            
            # Set the HTML body
            msg.html = render_template('email_reset.html', reset_url=reset_url)
            
            try:
                mail.send(msg)
                flash("A professional reset link has been sent to your email.", "info")
            except Exception as e:
                flash("Error sending email. Check your Mailtrap credentials.", "danger")

        else:
            flash("If an account exists with that email, a reset link has been sent.", "info")
            
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    user = User.query.filter_by(reset_token=token).first()

    # Verify token exists and hasn't expired
    if not user or user.token_expiry < datetime.utcnow():
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password and len(new_password) >= 8:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            user.reset_token = None # Clear the token so it can't be used again
            user.token_expiry = None
            user.password_last_changed = datetime.now(timezone.utc)
            current_user.password_last_changed = datetime.now(timezone.utc)
            db.session.commit()
            flash("Your password has been reset!", "success")
            return redirect(url_for('login'))
        else:
            flash("Passwords must match and be 8+ characters.", "warning")

    return render_template('reset_password.html') # A form identical to your profile password section

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
    
    # Get the search query from the URL (e.g., /admin?search=john)
    search_query = request.args.get('search', '')
    # Build the base query
    query = User.query
    # If there's a search term, filter by username or email (case-insensitive)
    if search_query:
        query = query.filter(
            (User.username.ilike(f'%{search_query}%')) | 
            (User.email.ilike(f'%{search_query}%'))
        )

    # Sort by username, forced to lowercase so 'apple' and 'Apple' are treated equally
    users = query.order_by(func.lower(User.username).asc()).all()
    return render_template('admin.html', users=users)

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
    # 1. Handle Adding Books (POST logic remains the same)
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        new_book = Book(title=title, author=author)
        db.session.add(new_book)
        db.session.commit()
        flash("New book added to library.", "success")
        return redirect(url_for('librarian_dashboard'))

    # 2. Get Search and Filter Parameters for Interactions
    search_query = request.args.get('search', '')

    # 3. Base Queries
    books = Book.query.all()
    
    user_tz_name = request.cookies.get('timezone', 'UTC')
    local_tz = pytz.timezone(user_tz_name)
    today_local = datetime.now(local_tz).date()

    # Determine display count based on APP_START_DATE
    days_since_start = (today_local - APP_START_DATE).days + 1
    display_count = min(days_since_start, 14)

    user_activity = []
    
    if search_query:
        target_user = User.query.filter(User.username.ilike(f'%{search_query}%')).first()
        if target_user:
            user_read_dates = {
                pytz.utc.localize(i.timestamp).astimezone(local_tz).date() 
                for i in ReaderInteraction.query.filter_by(user_id=target_user.id).all()
            }
            
            for i in range(display_count - 1, -1, -1):
                d = today_local - timedelta(days=i)
                user_activity.append({'date': d, 'is_read': d in user_read_dates, 'is_today': d == today_local})

    # We start with the ReaderInteraction query but JOIN User and Book
    interactions_query = ReaderInteraction.query.join(User).join(Book)

    # 4. Apply Case-Insensitive Search
    if search_query:
        interactions_query = interactions_query.filter(
            (User.username.ilike(f'%{search_query}%')) |
            (Book.title.ilike(f'%{search_query}%')) |
            (Book.author.ilike(f'%{search_query}%'))
        )

    # 5. Finalize and Order
    all_interactions = interactions_query.order_by(ReaderInteraction.id.desc()).all()
    
    return render_template('librarian.html', 
                           books=books, 
                           interactions=all_interactions,
                           search_query=search_query, 
                           user_activity=user_activity)

@app.route('/librarian/report/<int:user_id>')
@login_required
@role_required('librarian')
def download_report(user_id):
    # 1. Fetch User and Activity Data
    user = User.query.get_or_404(user_id)
    user_tz = request.cookies.get('timezone', 'UTC')
    local_tz = pytz.timezone(user_tz)
    
    # Get last 14 days of data
    today = datetime.now(local_tz).date()
    interactions = ReaderInteraction.query.filter_by(user_id=user.id).all()
    
    # 2. Initialize PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", 'B', 16)
    
    # Header
    pdf.cell(190, 10, f"Reading Progress Report: {user.username}", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.set_font("helvetica", size=10)
    pdf.cell(190, 10, f"Generated on: {today.strftime('%B %d, %Y')}", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(10)
    
    # 3. Create the Activity Table
    pdf.set_font("helvetica", 'B', 12)
    pdf.cell(40, 10, "Date", border=1)
    pdf.cell(30, 10, "Status", border=1)
    pdf.cell(120, 10, "Book Read", border=1, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("helvetica", size=10)
    # Loop back 14 days
    for i in range(13, -1, -1):
        d = today - timedelta(days=i)
        # Find if user read on this day
        daily_read = next((item for item in interactions if 
                           pytz.utc.localize(item.timestamp).astimezone(local_tz).date() == d), None)
        
        pdf.cell(40, 10, d.strftime('%Y-%m-%d'), border=1)
        pdf.cell(30, 10, "READ" if daily_read else "MISSED", border=1)
        pdf.cell(120, 10, daily_read.book.title[:50] if daily_read else "-", border=1, new_x="LMARGIN", new_y="NEXT")

    # 4. Return as File Download
    response = make_response(bytes(pdf.output()))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=report_{user.username}.pdf'
    return response

@app.route('/delete_book/<int:id>')
@login_required
@role_required('librarian')
def delete_book(id):
    book = Book.query.get(id)
    db.session.delete(book)
    db.session.commit()
    return redirect(url_for('librarian_dashboard'))

@app.route('/delete_comment/<int:interaction_id>', methods=['POST'])
@login_required
def delete_comment(interaction_id):
    # 1. Security Check: Only librarians can delete
    if current_user.role != 'librarian':
        flash("Unauthorized: Only librarians can delete comments.", "danger")
        return redirect(url_for('reader_dashboard'))

    # 2. Find and Delete the comment
    comment_to_delete = ReaderInteraction.query.get_or_404(interaction_id)
    
    try:
        db.session.delete(comment_to_delete)
        db.session.commit()
        flash("Comment successfully removed.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error deleting comment. Please try again.", "danger")

    return redirect(url_for('librarian_dashboard'))

APP_START_DATE = date(2026, 1, 21)

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
            (Book.title.icontains(search_query)) | 
            (Book.author.icontains(search_query))
        )

    pagination = query.paginate(page=page, per_page=per_page)
    # Total count for the user
    total_results = pagination.total

    # Get user's local timezone from cookie
    user_tz_name = request.cookies.get('timezone', 'UTC')
    local_tz = pytz.timezone(user_tz_name)
    today_local = datetime.now(local_tz).date()

    # Calculate how many days to show (up to 14, but not before APP_START_DATE)
    days_since_start = (today_local - APP_START_DATE).days + 1
    display_count = min(days_since_start, 14)

    # Get interaction dates
    interactions = ReaderInteraction.query.filter_by(user_id=current_user.id).all()
    read_dates = set()
    for interaction in interactions:
        utc_dt = pytz.utc.localize(interaction.timestamp)
        read_dates.add(utc_dt.astimezone(local_tz).date())

    # Generate the limited list
    relevant_days = []
    # Loop from (display_count - 1) down to 0
    for i in range(display_count - 1, -1, -1):
        d = today_local - timedelta(days=i)
        relevant_days.append({
            'date': d,
            'is_read': d in read_dates,
            'is_today': d == today_local
        })

    user_comments = {i.book_id: i.comment for i in interactions}
    history = ReaderInteraction.query.filter_by(user_id=current_user.id).order_by(ReaderInteraction.timestamp.desc()).all()
    stats = get_reader_stats(current_user.id)
    return render_template('reader.html',
                           stats=stats, 
                           pagination=pagination, 
                           total_results=total_results, 
                           history=history,
                           user_comments=user_comments,
                           search_query=search_query,
                           days_history=relevant_days)

@app.route('/reader/comment/<int:book_id>', methods=['POST'])
@login_required
@role_required('reader')
def add_comment(book_id):
    comment = request.form.get('comment', '').strip()
    # Split by any whitespace and filter out empty strings
    words = [w for w in comment.split() if w]
    word_count = len(words)

    if word_count < 30:
        flash(f"Your comment is only {word_count} words. Please write at least 30 words to share a meaningful reflection.", "warning")
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
        curr_pw_input = request.form.get('current_password')
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # 1. CRITICAL: Verify the current password first
        if not check_password_hash(current_user.password, curr_pw_input):
            flash("Incorrect current password. Changes could not be saved.", "danger")
            return redirect(url_for('profile'))

        # 2. Update Basic Info
        current_user.username = new_username
        current_user.email = new_email

        # 3. Handle Password Change (if provided)
        if new_password:
            if new_password == confirm_password and len(new_password) >= 8:
                current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                flash("Profile and password updated successfully!", "success")
            else:
                flash("New passwords must match and be at least 8 characters.", "warning")
                return redirect(url_for('profile'))
        else:
            flash("Profile updated successfully!", "success")

        db.session.commit()
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

@app.template_filter('to_local')
def to_local(dt):
    if not dt:
        return ""
    
    # 1. Get the timezone from the cookie, default to 'UTC' if not found
    user_tz = request.cookies.get('timezone', 'UTC')
    
    try:
        # 2. Localize the naive UTC datetime from the DB
        utc_dt = pytz.utc.localize(dt)
        # 3. Convert to the detected timezone
        local_tz = pytz.timezone(user_tz)
        local_dt = utc_dt.astimezone(local_tz)
        return local_dt.strftime('%Y-%m-%d %H:%M')
    except Exception:
        # Fallback if something goes wrong with the cookie string
        return dt.strftime('%Y-%m-%d %H:%M')

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
