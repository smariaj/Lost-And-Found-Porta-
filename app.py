from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from PIL import Image
from uuid import uuid4
import imagehash
from functools import wraps
import os
import logging
from datetime import datetime
import re

# ------------------ CREATE FLASK APP ------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'

# ------------------ DATABASE & LOGIN ------------------
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# ------------------ USER MODEL ------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('Item', backref='owner', lazy=True, cascade='all, delete-orphan')

    def is_admin(self):
        return self.role == 'admin'

# ------------------ ITEM MODEL ------------------
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    item_type = db.Column(db.String(10), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    image_path = db.Column(db.String(200))
    status = db.Column(db.String(50), default='With Finder')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ UPLOAD CONFIG ------------------
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(file):
    try:
        with Image.open(file) as img:
            img.verify()
        file.seek(0)
        return True
    except Exception:
        return False

# ------------------ LOGGING ------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[logging.FileHandler('app.log'), logging.StreamHandler()]
)

# ------------------ MAIL CONFIG ------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
mail = Mail(app)

def send_match_email(to_email, new_item, matched_item):
    try:
        subject = "Lost & Found Match Alert!"
        body = f"""Hi,

A potential match has been found for your item:

Your Item: {matched_item.title} ({matched_item.item_type})
Matched With: {new_item.title} ({new_item.item_type})
Location: {new_item.location}, Date: {new_item.date}

Please login to review this match.

Best regards,
Lost & Found Team"""
        msg = Message(subject, recipients=[to_email], body=body)
        mail.send(msg)
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# ------------------ IMAGE MATCHING ------------------
def find_image_matches(new_item):
    if not new_item.image_path or not os.path.exists(os.path.join('static', new_item.image_path)):
        return []
    
    try:
        if new_item.item_type == 'Found':
            potential_matches = Item.query.filter_by(item_type='Lost').all()
        else:
            potential_matches = Item.query.filter_by(item_type='Found').all()

        matches = []
        hash_new = imagehash.average_hash(Image.open(os.path.join('static', new_item.image_path)))
        
        for item in potential_matches:
            if not item.image_path:
                continue
            try:
                hash_existing = imagehash.average_hash(Image.open(os.path.join('static', item.image_path)))
                if hash_new - hash_existing < 5:
                    matches.append(item)
            except Exception:
                continue
                
        return matches
    except Exception as e:
        logging.error(f"Image matching error: {e}")
        return []

# ------------------ TEXT MATCHING ------------------
def find_text_matches(new_item):
    if new_item.item_type == 'Found':
        potential_matches = Item.query.filter_by(item_type='Lost').all()
    else:
        potential_matches = Item.query.filter_by(item_type='Found').all()

    matches = []
    for item in potential_matches:
        title_match = new_item.title.lower() in item.title.lower() or item.title.lower() in new_item.title.lower()
        category_match = item.category.lower() == new_item.category.lower()
        location_match = new_item.location.lower() in item.location.lower()
        
        if title_match and category_match and location_match:
            matches.append(item)
            
    return matches

# ------------------ VALIDATION ------------------
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain digit"
    return True, "Password is strong"

# ------------------ DECORATORS ------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ------------------ ERROR HANDLERS ------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# ------------------ ROUTES ------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not all([name, email, password]):
            flash('All fields are required.', 'error')
            return render_template('register.html')
            
        if not is_valid_email(email):
            flash('Invalid email address.', 'error')
            return render_template('register.html')
            
        is_strong, msg = is_strong_password(password)
        if not is_strong:
            flash(msg, 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('login'))
            
        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            user = User(name=name, email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin():
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
        
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
        
    search_title = request.args.get('title', '').strip()
    filter_type = request.args.get('type', '')
    filter_category = request.args.get('category', '').strip()
    filter_location = request.args.get('location', '').strip()

    query = Item.query.filter_by(user_id=current_user.id)
    
    if search_title:
        query = query.filter(Item.title.ilike(f"%{search_title}%"))
    if filter_type in ['Lost', 'Found']:
        query = query.filter_by(item_type=filter_type)
    if filter_category:
        query = query.filter(Item.category.ilike(f"%{filter_category}%"))
    if filter_location:
        query = query.filter(Item.location.ilike(f"%{filter_location}%"))

    items = query.order_by(Item.created_at.desc()).all()
    items_with_matches = []
    
    for item in items:
        text_matches = find_text_matches(item)
        image_matches = find_image_matches(item)
        all_matches = list({m.id: m for m in text_matches + image_matches}.values())
        items_with_matches.append({'item': item, 'matches': all_matches})

    return render_template('dashboard.html', 
                         items_with_matches=items_with_matches,
                         search_title=search_title, 
                         filter_type=filter_type,
                         filter_category=filter_category, 
                         filter_location=filter_location)

@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    found_items = Item.query.filter(
        Item.item_type == 'Found',
        Item.status != 'Returned to Owner'
    ).order_by(Item.created_at.desc()).all()

    lost_items = Item.query.filter(
        Item.item_type == 'Lost',
        Item.status != 'Returned to Owner'
    ).order_by(Item.created_at.desc()).all()

    pending_items = Item.query.filter_by(status='Pending Verification').order_by(Item.created_at.desc()).all()

    found_items_with_matches = []
    for f_item in found_items:
        text_matches = find_text_matches(f_item)
        image_matches = find_image_matches(f_item)
        all_matches = list({m.id: m for m in text_matches + image_matches}.values())
        found_items_with_matches.append({'item': f_item, 'matches': all_matches})

    return render_template('admin_dashboard.html',
                       found_items_with_matches=found_items_with_matches,
                       lost_items=lost_items,
                       pending_items=pending_items)

@app.route('/admin_history')
@login_required
@admin_required
def admin_history():
    returned_items = Item.query.filter_by(status='Returned to Owner').order_by(Item.updated_at.desc()).all()
    return render_template('admin_history.html', returned_items=returned_items)

@app.route('/update_status/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def update_status(item_id):
    new_status = request.form.get('status')
    item = Item.query.get_or_404(item_id)
    
    if new_status:
        item.status = new_status
        db.session.commit()
        flash(f"Status updated to {new_status}", 'success')
        
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/verify_match', methods=['POST'])
@login_required
@admin_required
def verify_match():
    found_id = request.form.get('found_id', type=int)
    lost_id = request.form.get('lost_id', type=int)
    
    found_item = Item.query.get(found_id)
    lost_item = Item.query.get(lost_id)
    
    if found_item and lost_item:
        found_item.status = 'Returned to Owner'
        lost_item.status = 'Returned to Owner'
        db.session.commit()
        flash('Items marked as returned.', 'success')
    else:
        flash('Invalid items.', 'error')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if current_user.is_admin():
        flash('Admins cannot add items.', 'warning')
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        item_type = request.form.get('item_type', '')
        category = request.form.get('category', '').strip()
        location = request.form.get('location', '').strip()
        date = request.form.get('date', '')

        if not all([title, description, item_type, category, location, date]):
            flash('All fields are required.', 'error')
            return render_template('add_item.html')

        file = request.files.get('image')
        image_path = ''
        
        if file and file.filename:
            if not allowed_file(file.filename):
                flash('Invalid file type.', 'error')
                return render_template('add_item.html')
            
            if not validate_image(file):
                flash('Invalid image file.', 'error')
                return render_template('add_item.html')
            
            ext = file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid4().hex}.{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            image_path = f"uploads/{unique_filename}"

        new_item = Item(
            user_id=current_user.id,
            title=title,
            description=description,
            item_type=item_type,
            category=category,
            location=location,
            date=date,
            image_path=image_path
        )
        
        db.session.add(new_item)
        db.session.commit()

        matches = find_text_matches(new_item) + find_image_matches(new_item)
        if matches:
            match_titles = ', '.join([m.title for m in matches[:3]])
            flash(f"Item reported! Potential matches: {match_titles}", 'success')
        else:
            flash('Item reported successfully!', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_item.html')

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    if item.user_id != current_user.id and not current_user.is_admin():
        abort(403)
        
    if request.method == 'POST':
        item.title = request.form.get('title', '').strip()
        item.description = request.form.get('description', '').strip()
        item.category = request.form.get('category', '').strip()
        item.location = request.form.get('location', '').strip()
        item.date = request.form.get('date', '')
        
        file = request.files.get('image')
        if file and file.filename and allowed_file(file.filename) and validate_image(file):
            if item.image_path and os.path.exists(os.path.join('static', item.image_path)):
                os.remove(os.path.join('static', item.image_path))
            
            ext = file.filename.rsplit('.', 1)[1].lower()
            unique_filename = f"{uuid4().hex}.{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            item.image_path = f"uploads/{unique_filename}"
        
        db.session.commit()
        flash('Item updated!', 'success')
        
        if current_user.is_admin():
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    
    return render_template('edit_item.html', item=item)

@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    if item.user_id != current_user.id and not current_user.is_admin():
        abort(403)
        
    if item.image_path and os.path.exists(os.path.join('static', item.image_path)):
        os.remove(os.path.join('static', item.image_path))
        
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted!', 'success')
    
    if current_user.is_admin():
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/how_it_works')
def how_it_works():
    return render_template('how_it_works.html')


# ------------------ INITIALIZE DATABASE ------------------
def init_db():
    with app.app_context():
        db.create_all()
        
        admin_email = 'admin@lostfound.com'
        admin_password = 'Admin123!'
        
        if not User.query.filter_by(email=admin_email).first():
            hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
            admin_user = User(name='Admin', email=admin_email, password=hashed_password, role='admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created")

# ------------------ RUN ------------------
if __name__ == '__main__':
    init_db()
    print("Server starting...")
    print("Admin: admin@lostfound.com / Admin123!")
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))