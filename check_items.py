from app import app, db, Item  # import the app too

with app.app_context():
    items = Item.query.all()
    if not items:
        print("No items found.")
    for i in items:
        print(f"ID: {i.id}, Title: {i.title}, Type: {i.item_type}, User ID: {i.user_id}")
