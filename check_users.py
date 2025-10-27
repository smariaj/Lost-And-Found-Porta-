from app import app, db, User

with app.app_context():
    users = User.query.all()
    if not users:
        print("No users found.")
    for u in users:
        print(f"ID: {u.id}, Name: {u.name}, Email: {u.email}")
