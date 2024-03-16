from app import app, db, User

def make_user_admin(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_admin = True
        db.session.commit()
        print(f"User {username} has been granted admin rights.")
    else:
        print(f"User {username} not found.")
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
    else:
        with app.app_context():
            make_user_admin(sys.argv[1])
