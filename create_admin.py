from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User(name='watchman', email='watchman@college.edu', password=generate_password_hash('adminpass', method='pbkdf2:sha256'), role='admin')
    db.session.add(admin)
    db.session.commit()
    print("Admin created:", admin.email)
